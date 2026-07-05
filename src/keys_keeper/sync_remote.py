"""S3 transport: hand-rolled AWS Signature V4 over the stdlib `urllib`.

No boto3 / botocore / requests — keeps the zero-runtime-deps promise. Works
against any S3-compatible endpoint (AWS S3, Cloudflare R2, Backblaze B2, MinIO,
Wasabi) using path-style addressing by default.

The signer is locked by an official AWS SigV4 known-answer vector in
tests/test_sigv4.py — do not "optimize" the canonical-request construction
without re-running it; SigV4 is byte-exact or it is broken.
"""
from __future__ import annotations

import hashlib
import hmac
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

from keys_keeper.backend import Sealed

_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


# ---------------- transport errors ----------------

class TransportError(RuntimeError):
    """Network / timeout / unexpected status."""


class AuthError(TransportError):
    """401/403 — bad credentials or denied."""


class NotFound(TransportError):
    """404 — object/bucket missing."""


class PreconditionFailed(TransportError):
    """412/409 — a conditional write (If-None-Match) lost the race."""


# ---------------- SigV4 ----------------

def uri_encode(s: str, *, encode_slash: bool) -> str:
    """RFC-3986 percent-encoding per the SigV4 spec. NOT urllib.parse.quote.

    Unreserved chars pass through; everything else is %XX with UPPERCASE hex.
    `/` is preserved in the path (encode_slash=False) but encoded in query
    values (encode_slash=True). Space is always %20, never +.
    """
    out = []
    for b in s.encode("utf-8"):
        c = chr(b)
        if c in _UNRESERVED:
            out.append(c)
        elif c == "/" and not encode_slash:
            out.append("/")
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def encode_query(query: dict[str, str]) -> str:
    """Canonical query string: encode names+values, sort by encoded name."""
    if not query:
        return ""
    pairs = [
        (uri_encode(k, encode_slash=True), uri_encode(str(v), encode_slash=True))
        for k, v in query.items()
    ]
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


@dataclass
class _SignParts:
    canonical_request: str
    hashed_canonical_request: str
    string_to_sign: str
    signing_key: bytes
    signature: str
    authorization: str
    amz_date: str
    signed_headers: str


class S3Signer:
    """Signs a request with AWS Signature V4. `secret_key` stays Sealed until
    the HMAC signing-key derivation — it never enters a header or URL (S5)."""

    def __init__(self, access_key_id: str, secret_key: Sealed, region: str,
                 service: str = "s3"):
        self.access_key_id = access_key_id
        self._secret_key = secret_key
        self.region = region
        self.service = service

    def _signing_key(self, datestamp: str) -> bytes:
        def _h(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
        k_date = _h(("AWS4" + self._secret_key.unseal()).encode("utf-8"), datestamp)
        k_region = _h(k_date, self.region)
        k_service = _h(k_region, self.service)
        return _h(k_service, "aws4_request")

    def components(self, method: str, path: str, query: dict[str, str],
                   headers: dict[str, str], body: bytes, *,
                   amz_date: str | None = None) -> _SignParts:
        amz_date = amz_date or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        datestamp = amz_date[:8]

        signed = dict(headers)
        signed["x-amz-date"] = amz_date
        # canonical headers: lowercased name, trimmed+ws-collapsed value, sorted
        norm = {k.lower(): " ".join(str(v).split()) for k, v in signed.items()}
        names = sorted(norm)
        canonical_headers = "".join(f"{n}:{norm[n]}\n" for n in names)
        signed_headers = ";".join(names)

        hashed_payload = hashlib.sha256(body).hexdigest()
        canonical_request = "\n".join([
            method.upper(),
            uri_encode(path, encode_slash=False),
            encode_query(query),
            canonical_headers,
            signed_headers,
            hashed_payload,
        ])
        hcr = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        scope = f"{datestamp}/{self.region}/{self.service}/aws4_request"
        string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hcr])
        signing_key = self._signing_key(datestamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        authorization = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return _SignParts(canonical_request, hcr, string_to_sign, signing_key,
                          signature, authorization, amz_date, signed_headers)

    def sign(self, method: str, path: str, query: dict[str, str],
             headers: dict[str, str], body: bytes, *,
             amz_date: str | None = None) -> dict[str, str]:
        """Return the headers to send: the caller's headers + x-amz-date +
        Authorization."""
        p = self.components(method, path, query, headers, body, amz_date=amz_date)
        out = dict(headers)
        out["x-amz-date"] = p.amz_date
        out["Authorization"] = p.authorization
        return out


# ---------------- HTTP opener (proxy policy) ----------------
#
# S3 transport goes DIRECT by default — it bypasses any system/env HTTP proxy.
# A secrets backup talking to a fixed S3 endpoint wants a deterministic path; a
# flaky local VPN/proxy (e.g. a CONNECT tunnel that returns "503 Service
# Unavailable") must not be able to break, or sit in front of, the encrypted
# blob. Set sync.proxy = "system" to honour the OS/env proxy (the old
# behaviour), or "http://host:port" to force one explicitly.
_OPENERS: dict = {}


def _opener_for(proxy: str):
    key = proxy or "direct"
    op = _OPENERS.get(key)
    if op is None:
        if key == "system":
            op = build_opener()                          # honour system/env proxy
        elif key in ("direct", "none", "off", ""):
            op = build_opener(ProxyHandler({}))          # bypass all proxies
        else:
            op = build_opener(ProxyHandler({"http": key, "https": key}))
        _OPENERS[key] = op
    return op


def urlopen(req, timeout=None, *, proxy: str = "direct"):
    """Module-level transport seam (monkeypatched in tests). Routes the request
    through a cached opener selected by the sync `proxy` policy."""
    return _opener_for(proxy).open(req, timeout=timeout)


# ---------------- S3 verbs ----------------

class S3Remote:
    """Minimal S3 object store over signed urllib requests.

    Implements the RemoteStore shape the sync engine depends on:
    put_object / get_object / head_object / list_objects / delete_object,
    plus probe_cas() to detect providers that ignore If-None-Match.
    """

    def __init__(self, *, signer: S3Signer, endpoint: str, bucket: str,
                 prefix: str = "", addressing: str = "path", timeout: float = 15.0,
                 proxy: str = "direct"):
        self.signer = signer
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.addressing = addressing
        self.timeout = timeout
        self._proxy = proxy or "direct"
        u = urlparse(self.endpoint)
        self._scheme = u.scheme
        self._endpoint_host = u.netloc

    # -- key/path helpers --
    def _full_key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def _host(self) -> str:
        if self.addressing == "virtual":
            return f"{self.bucket}.{self._endpoint_host}"
        return self._endpoint_host

    def _resource_path(self, key: str, *, bucket_level: bool = False) -> str:
        if self.addressing == "virtual":
            return "/" if bucket_level else "/" + key
        return f"/{self.bucket}" if bucket_level else f"/{self.bucket}/{key}"

    def _url(self, path: str, query_str: str) -> str:
        url = f"{self._scheme}://{self._host()}{uri_encode(path, encode_slash=False)}"
        return f"{url}?{query_str}" if query_str else url

    # -- request core --
    def _request(self, method: str, path: str, *, query: dict[str, str] | None = None,
                 body: bytes = b"", extra_headers: dict[str, str] | None = None):
        query = query or {}
        headers = {
            "host": self._host(),
            "x-amz-content-sha256": hashlib.sha256(body).hexdigest(),
        }
        if extra_headers:
            headers.update(extra_headers)
        signed = self.signer.sign(method, path, query, headers, body)
        if body:
            signed["Content-Length"] = str(len(body))
        url = self._url(path, encode_query(query))
        req = Request(url, data=body if body else None, method=method)
        for k, v in signed.items():
            req.add_header(k, v)
        try:
            resp = urlopen(req, timeout=self.timeout, proxy=self._proxy)
            return resp.status, dict(resp.headers), resp.read()
        except HTTPError as e:
            status = e.code
            # NB: we deliberately do NOT splice the provider's error body into the
            # message — S3 error XML routinely echoes back the AWSAccessKeyId and
            # the StringToSign, which would leak to stderr/logs (S2/S5).
            if status == 404:
                raise NotFound(f"{method} {path}: 404") from None
            if status in (401, 403):
                raise AuthError(f"{method} {path}: {status} (check credentials)") from None
            if status in (409, 412):
                raise PreconditionFailed(f"{method} {path}: {status}") from None
            raise TransportError(f"{method} {path}: HTTP {status}") from None
        except (URLError, OSError, TimeoutError) as e:
            # A proxy CONNECT failure ("Tunnel connection failed: 503 …") carries
            # no S3 credentials, so it is safe to surface and point at the fix.
            low = str(e).lower()
            hint = ""
            if "tunnel connection failed" in low or "proxy" in low:
                hint = (' — the request was routed through an HTTP proxy; set '
                        'sync.proxy="direct" in config.toml (or clear the system '
                        'proxy / set NO_PROXY) to connect straight to S3')
            raise TransportError(f"{method} {path}: {e}{hint}") from None

    # -- public verbs --
    def put_object(self, key: str, body: bytes, *, if_none_match: str | None = None,
                   content_type: str = "application/octet-stream") -> str:
        extra = {"Content-Type": content_type}
        if if_none_match is not None:
            extra["If-None-Match"] = if_none_match
        _, headers, _ = self._request(
            "PUT", self._resource_path(self._full_key(key)), body=body, extra_headers=extra
        )
        return (headers.get("ETag") or headers.get("Etag") or "").strip('"')

    def get_object(self, key: str) -> bytes:
        _, _, body = self._request("GET", self._resource_path(self._full_key(key)))
        return body

    def head_object(self, key: str) -> dict | None:
        try:
            _, headers, _ = self._request("HEAD", self._resource_path(self._full_key(key)))
            return headers
        except NotFound:
            return None

    def list_objects(self, prefix: str) -> list[str]:
        """List keys under `<configured prefix>/<prefix>` (paginated)."""
        full = self._full_key(prefix)
        keys: list[str] = []
        token: str | None = None
        while True:
            query = {"list-type": "2", "prefix": full}
            if token:
                query["continuation-token"] = token
            _, _, body = self._request(
                "GET", self._resource_path("", bucket_level=True), query=query
            )
            root = ET.fromstring(body)
            ns = root.tag[: root.tag.find("}") + 1] if "}" in root.tag else ""
            for c in root.findall(f"{ns}Contents"):
                k = c.findtext(f"{ns}Key")
                if k is not None:
                    keys.append(k[len(self.prefix) + 1:] if self.prefix else k)
            truncated = (root.findtext(f"{ns}IsTruncated") or "false").lower() == "true"
            token = root.findtext(f"{ns}NextContinuationToken")
            if not truncated or not token:
                break
        return keys

    def delete_object(self, key: str) -> None:
        try:
            self._request("DELETE", self._resource_path(self._full_key(key)))
        except NotFound:
            pass  # idempotent

    def probe_cas(self) -> bool:
        """True iff the provider honours create-if-absent (If-None-Match:*).

        Writes a throwaway key twice with If-None-Match:*; a compliant backend
        rejects the second with 412/409. Cleans up afterwards.
        """
        probe_key = ".kk-cas-probe"
        self.delete_object(probe_key)
        self.put_object(probe_key, b"1", if_none_match="*")
        try:
            self.put_object(probe_key, b"2", if_none_match="*")
            honored = False  # second write succeeded → precondition ignored
        except PreconditionFailed:
            honored = True
        finally:
            self.delete_object(probe_key)
        return honored
