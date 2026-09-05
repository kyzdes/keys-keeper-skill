"""Hardened stdlib HTTP client for the keys-keeper VPS sync service.

The client deliberately treats encrypted snapshots, signed commits, and wrapped
vault keys as opaque API data.  Cryptographic validation belongs to the KK2
protocol layer; this module only provides bounded, authenticated transport.
"""
from __future__ import annotations

import base64
import ipaddress
import json
from collections.abc import Callable, Mapping
from typing import Any, TypeAlias
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from keys_keeper.backend import Sealed


JsonObject: TypeAlias = dict[str, Any]
SecretSource: TypeAlias = Sealed | Callable[[], Sealed | str]

DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_REQUEST_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024


# ---------------- domain errors ----------------


class VpsClientError(RuntimeError):
    """Base class for VPS sync client failures."""


class VpsConfigurationError(VpsClientError):
    """Unsafe or unusable local client configuration."""


class VpsTransportError(VpsClientError):
    """Network failure or an unexpected HTTP status."""


class VpsAuthenticationError(VpsTransportError):
    """The server rejected the bearer token or device identity (401/403)."""


class VpsNotFoundError(VpsTransportError):
    """The requested vault resource does not exist (404)."""


class VpsInviteExpiredError(VpsTransportError):
    """A one-time device invitation has expired (410)."""


class VpsConflictError(VpsTransportError):
    """The expected parent is no longer the vault head (409)."""


class VpsPayloadTooLargeError(VpsTransportError):
    """A request or response exceeded an allowed size (413 or local limit)."""


class VpsValidationError(VpsTransportError):
    """The request was rejected as semantically invalid (422)."""


class VpsProtocolError(VpsTransportError):
    """The server returned a malformed or unexpected response."""


# Short aliases make integration code readable while retaining a VPS-specific
# canonical name for callers that use several transports in one process.
AuthenticationError = VpsAuthenticationError
NotFoundError = VpsNotFoundError
InviteExpiredError = VpsInviteExpiredError
ConflictError = VpsConflictError
PayloadTooLargeError = VpsPayloadTooLargeError
UnprocessableEntityError = VpsValidationError
ProtocolError = VpsProtocolError
TransportError = VpsTransportError


# ---------------- HTTP opener (proxy policy) ----------------


class _NoRedirectHandler(HTTPRedirectHandler):
    """Never replay an Authorization header to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_OPENERS: dict[str, Any] = {}


def _opener_for(proxy: str):
    key = proxy or "direct"
    opener = _OPENERS.get(key)
    if opener is None:
        if key == "system":
            proxy_handler = ProxyHandler()
        elif key in ("direct", "none", "off", ""):
            proxy_handler = ProxyHandler({})
        else:
            proxy_handler = ProxyHandler({"http": key, "https": key})
        opener = build_opener(proxy_handler, _NoRedirectHandler())
        _OPENERS[key] = opener
    return opener


def urlopen(req, timeout=None, *, proxy: str = "direct"):
    """Module-level seam for deterministic tests and explicit proxy routing."""
    return _opener_for(proxy).open(req, timeout=timeout)


# ---------------- validation and JSON helpers ----------------


def _is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    host = hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalize_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise VpsConfigurationError("sync server URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise VpsConfigurationError("sync server URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise VpsConfigurationError("sync server URL must not contain query or fragment")
    if parsed.scheme != "https" and not _is_loopback(parsed.hostname):
        raise VpsConfigurationError(
            "sync server requires HTTPS; plain HTTP is allowed only for loopback testing"
        )
    return value.rstrip("/")


def _normalize_proxy(value: str) -> str:
    if value in ("direct", "system"):
        return value
    parsed = urlparse(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise VpsConfigurationError(
            "proxy must be 'direct', 'system', or an HTTP(S) URL without credentials"
        )
    return value.rstrip("/")


def _segment(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(ch) < 0x20 for ch in value):
        raise VpsValidationError(f"{label} must be a non-empty text identifier")
    return quote(value, safe="")


def _secret_value(source: SecretSource, label: str) -> str:
    try:
        value = source() if callable(source) else source
    except Exception:
        raise VpsAuthenticationError(f"{label} provider failed") from None
    if isinstance(value, Sealed):
        plaintext = value.unseal()
    elif callable(source) and isinstance(value, str):
        # A callback is permitted to bridge an external credential provider
        # whose API cannot return Sealed.  Direct bare strings are rejected.
        plaintext = value
    else:
        raise VpsConfigurationError(f"{label} must be Sealed or supplied by a callback")
    if not plaintext or any(ch.isspace() for ch in plaintext):
        raise VpsAuthenticationError(f"{label} is missing or malformed")
    return plaintext


def _reject_constant(value: str):
    raise ValueError(f"non-finite JSON number {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> JsonObject:
    obj: JsonObject = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON object key")
        obj[key] = value
    return obj


def _decode_json(body: bytes) -> Any:
    try:
        text = body.decode("utf-8", errors="strict")
        return json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise VpsProtocolError("sync server returned malformed JSON") from None


def _encode_json(payload: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(payload),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        # json's exception can contain repr(user_value); do not splice it into a
        # transport error because payloads may contain credential material.
        raise VpsValidationError("request payload is not valid JSON data") from None


def _header(headers: Any, name: str) -> str | None:
    if hasattr(headers, "get"):
        value = headers.get(name)
        if value is None:
            value = headers.get(name.lower())
        return None if value is None else str(value)
    return None


def _redact(message: object, sensitive_values: tuple[str, ...]) -> str:
    text = str(message)
    for value in sensitive_values:
        if value:
            text = text.replace(value, "<redacted>")
    return text


def _opaque_strings(value: Any) -> tuple[str, ...]:
    """Collect strings from an opaque envelope solely for error redaction."""
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, Mapping):
        items: list[str] = []
        for nested in value.values():
            items.extend(_opaque_strings(nested))
        return tuple(items)
    if isinstance(value, (list, tuple)):
        items = []
        for nested in value:
            items.extend(_opaque_strings(nested))
        return tuple(items)
    return ()


def _b64url(data: bytes) -> str:
    """Canonical unpadded URL-safe base64 used by the sync wire protocol."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


_SAFE_SERVER_ERROR_CODES = {
    "already_revoked",
    "cas_conflict",
    "commit_conflict",
    "device_conflict",
    "device_inactive",
    "invalid_invite_secret",
    "invite_expired",
    "invite_not_claimed",
    "invite_used",
    "not_found",
    "root_revoke_forbidden",
    "root_required",
    "wrong_approver",
    "wrong_vault",
}


def _status_error(
    method: str, path: str, status: int, server_code: str | None = None
) -> VpsTransportError:
    safe_code = server_code if server_code in _SAFE_SERVER_ERROR_CODES else None
    message = f"{method} {path}: HTTP {status}"
    if safe_code:
        message += f" [{safe_code}]"
    if status in (401, 403):
        return VpsAuthenticationError(message)
    if status == 404:
        return VpsNotFoundError(message)
    if status == 410:
        return VpsInviteExpiredError(message)
    if status == 409:
        return VpsConflictError(message)
    if status == 413:
        return VpsPayloadTooLargeError(message)
    if status == 422:
        return VpsValidationError(message)
    return VpsTransportError(message)


# ---------------- public client ----------------


class VpsSyncClient:
    """Bounded JSON client for ``keys-keeper-syncd``.

    ``token`` is held as a :class:`Sealed` value or obtained lazily from a
    callback.  It is unsealed only while constructing an authenticated request
    and is never placed in a URL or exception message.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: SecretSource | None = None,
        device_id: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        proxy: str = "direct",
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        if token is not None and not isinstance(token, Sealed) and not callable(token):
            raise VpsConfigurationError("bearer token must be Sealed or supplied by a callback")
        if device_id is not None and (not isinstance(device_id, str) or not device_id):
            raise VpsConfigurationError("device_id must be non-empty when supplied")
        if timeout <= 0:
            raise VpsConfigurationError("timeout must be positive")
        if max_request_bytes <= 0 or max_response_bytes <= 0:
            raise VpsConfigurationError("HTTP body limits must be positive")
        self.device_id = device_id
        self._token = token
        self.timeout = float(timeout)
        self._proxy = _normalize_proxy(proxy or "direct")
        self.max_request_bytes = int(max_request_bytes)
        self.max_response_bytes = int(max_response_bytes)

    def __repr__(self) -> str:
        proxy = self._proxy if self._proxy in ("direct", "system", "none", "off") else "<configured>"
        return (
            f"{type(self).__name__}(base_url={self.base_url!r}, "
            f"device_id={self.device_id!r}, token=<sealed>, "
            f"timeout={self.timeout!r}, proxy={proxy!r})"
        )

    def _auth_headers(self, *, include_device: bool) -> tuple[dict[str, str], str]:
        if self._token is None:
            raise VpsAuthenticationError("no bearer token is configured")
        token = _secret_value(self._token, "bearer token")
        headers = {"Authorization": f"Bearer {token}"}
        if include_device:
            if not self.device_id:
                raise VpsAuthenticationError("no device identity is configured")
            if "\r" in self.device_id or "\n" in self.device_id:
                raise VpsConfigurationError("device identity contains invalid characters")
            headers["X-Device-ID"] = self.device_id
        return headers, token

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        auth: bool = True,
        include_device: bool = True,
        expected_statuses: tuple[int, ...] = (200,),
        sensitive_values: tuple[str, ...] = (),
    ) -> Any:
        body = b"" if payload is None else _encode_json(payload)
        if len(body) > self.max_request_bytes:
            raise VpsPayloadTooLargeError("request body exceeds the configured limit")

        headers = {"Accept": "application/json"}
        secrets = sensitive_values
        if auth:
            auth_headers, bearer = self._auth_headers(include_device=include_device)
            headers.update(auth_headers)
            secrets = secrets + (bearer,)
        if payload is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
            headers["Content-Length"] = str(len(body))

        url = self.base_url + path
        req = Request(
            url,
            data=body if payload is not None else None,
            headers=headers,
            method=method,
        )
        response = None
        try:
            response = urlopen(req, timeout=self.timeout, proxy=self._proxy)
            raw_status = getattr(response, "status", None)
            if raw_status is None:
                raw_status = response.getcode()
            status = int(raw_status)
            if status not in expected_statuses:
                raise _status_error(method, path, status)

            if status == 204:
                return None
            response_headers = getattr(response, "headers", {})
            content_length = _header(response_headers, "Content-Length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError:
                    raise VpsProtocolError("sync server returned invalid Content-Length") from None
                if declared < 0:
                    raise VpsProtocolError("sync server returned invalid Content-Length")
                if declared > self.max_response_bytes:
                    raise VpsPayloadTooLargeError(
                        "response body exceeds the configured limit"
                    )

            content_type = _header(response_headers, "Content-Type")
            if content_type is None:
                raise VpsProtocolError("sync server response is missing Content-Type")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise VpsProtocolError("sync server returned a non-JSON response")
            parameters = [part.strip() for part in content_type.split(";")[1:]]
            for parameter in parameters:
                if parameter.lower().startswith("charset="):
                    charset = parameter.split("=", 1)[1].strip().strip('"').lower()
                    if charset not in ("utf-8", "utf8"):
                        raise VpsProtocolError("sync server JSON response is not UTF-8")
            content_encoding = _header(response_headers, "Content-Encoding")
            if content_encoding and content_encoding.lower() != "identity":
                raise VpsProtocolError("compressed sync responses are not accepted")

            data = response.read(self.max_response_bytes + 1)
            if len(data) > self.max_response_bytes:
                raise VpsPayloadTooLargeError("response body exceeds the configured limit")
            if not data:
                raise VpsProtocolError("sync server returned an empty JSON response")
            return _decode_json(data)
        except HTTPError as exc:
            server_code = None
            try:
                error_body = exc.read(min(self.max_response_bytes, 64 * 1024) + 1)
                if len(error_body) <= min(self.max_response_bytes, 64 * 1024):
                    decoded = _decode_json(error_body)
                    error = decoded.get("error") if isinstance(decoded, dict) else None
                    candidate = error.get("code") if isinstance(error, dict) else None
                    if isinstance(candidate, str):
                        server_code = candidate
            except (OSError, VpsClientError):
                pass
            raise _status_error(method, path, int(exc.code), server_code) from None
        except VpsClientError:
            raise
        except (URLError, TimeoutError, OSError) as exc:
            detail = _redact(exc, secrets)
            raise VpsTransportError(f"{method} {path}: transport failure: {detail}") from None
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    @staticmethod
    def _object(value: Any) -> JsonObject:
        if not isinstance(value, dict):
            raise VpsProtocolError("sync server JSON response must be an object")
        return value

    # -- vault bootstrap and commits --

    def create_vault(
        self,
        *,
        device_token: SecretSource,
        sign_public_key: str,
        wrap_public_key: str,
    ) -> JsonObject:
        """Create a vault using the configured admin bearer token.

        The initial device token is transported in the JSON body but is never
        included in errors.  Bootstrap intentionally omits ``X-Device-ID``.
        """
        plaintext_token = _secret_value(device_token, "device token")
        result = self._request(
            "POST",
            "/v1/vaults",
            payload={
                "device_token": plaintext_token,
                "sign_public_key": sign_public_key,
                "wrap_public_key": wrap_public_key,
            },
            include_device=False,
            expected_statuses=(200, 201),
            sensitive_values=(plaintext_token,),
        )
        return self._object(result)

    def get_head(self, vault_id: str) -> JsonObject | None:
        try:
            result = self._request(
                "GET", f"/v1/vaults/{_segment(vault_id, 'vault_id')}/head"
            )
        except VpsNotFoundError:
            return None
        return self._object(result)

    def get_commit(self, vault_id: str, commit_id: str) -> JsonObject:
        path = (
            f"/v1/vaults/{_segment(vault_id, 'vault_id')}/commits/"
            f"{_segment(commit_id, 'commit_id')}"
        )
        return self._object(self._request("GET", path))

    def list_commits(
        self,
        vault_id: str,
        *,
        after_sequence: int | None = None,
        limit: int = 100,
    ) -> JsonObject:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise VpsValidationError("commit list limit must be between 1 and 100")
        query: dict[str, str] = {"limit": str(limit)}
        if after_sequence is not None:
            if (
                not isinstance(after_sequence, int)
                or isinstance(after_sequence, bool)
                or after_sequence < 0
            ):
                raise VpsValidationError("after_sequence must be a non-negative integer")
            query["after_sequence"] = str(after_sequence)
        path = f"/v1/vaults/{_segment(vault_id, 'vault_id')}/commits?{urlencode(query)}"
        return self._object(self._request("GET", path))

    def append_commit(
        self,
        vault_id: str,
        *,
        commit_blob: bytes,
        snapshot_ciphertext: bytes,
        expected_parent: str | None,
    ) -> JsonObject:
        if not isinstance(commit_blob, bytes) or not isinstance(snapshot_ciphertext, bytes):
            raise VpsValidationError("commit_blob and snapshot_ciphertext must be bytes")
        if expected_parent is not None and not isinstance(expected_parent, str):
            raise VpsValidationError("expected_parent must be text or None")
        encoded_commit = _b64url(commit_blob)
        encoded_snapshot = _b64url(snapshot_ciphertext)
        result = self._request(
            "POST",
            f"/v1/vaults/{_segment(vault_id, 'vault_id')}/commits",
            payload={
                "expected_parent_commit_id": expected_parent,
                "commit_blob": encoded_commit,
                "snapshot_ciphertext": encoded_snapshot,
            },
            expected_statuses=(200, 201),
            sensitive_values=(encoded_commit, encoded_snapshot),
        )
        return self._object(result)

    # -- device membership --

    def list_devices(self, vault_id: str) -> JsonObject:
        path = f"/v1/vaults/{_segment(vault_id, 'vault_id')}/devices"
        return self._object(self._request("GET", path))

    def revoke_device(
        self,
        vault_id: str,
        revoked_device_id: str,
        *,
        expected_head: str | None,
        revocation_statement: str,
        revocation_signature: str,
    ) -> JsonObject:
        if not isinstance(revocation_statement, str) or not isinstance(
            revocation_signature, str
        ):
            raise VpsValidationError("revocation evidence must be canonical JSON text")
        path = (
            f"/v1/vaults/{_segment(vault_id, 'vault_id')}/devices/"
            f"{_segment(revoked_device_id, 'device_id')}/revoke"
        )
        result = self._request(
            "POST",
            path,
            payload={
                "expected_head_commit_id": expected_head,
                "revocation_statement": revocation_statement,
                "revocation_signature": revocation_signature,
            },
            expected_statuses=(200, 204),
        )
        return {} if result is None else self._object(result)

    # -- invite lifecycle --

    def create_invite(
        self,
        vault_id: str,
        *,
        secret_hash: str,
        expires_in_seconds: int,
    ) -> JsonObject:
        path = f"/v1/vaults/{_segment(vault_id, 'vault_id')}/invites"
        result = self._request(
            "POST",
            path,
            payload={
                "secret_hash": secret_hash,
                "expires_in_seconds": expires_in_seconds,
            },
            expected_statuses=(200, 201),
        )
        return self._object(result)

    def claim_invite(
        self,
        invite_id: str,
        *,
        secret: SecretSource,
        device_id: str,
        device_token: SecretSource,
        sign_public_key: str,
        wrap_public_key: str,
    ) -> JsonObject:
        invite_secret = _secret_value(secret, "invite secret")
        plaintext_token = _secret_value(device_token, "device token")
        result = self._request(
            "POST",
            f"/v1/invites/{_segment(invite_id, 'invite_id')}/claim",
            payload={
                "secret": invite_secret,
                "device_id": device_id,
                "device_token": plaintext_token,
                "sign_public_key": sign_public_key,
                "wrap_public_key": wrap_public_key,
            },
            auth=False,
            include_device=False,
            expected_statuses=(200, 201, 202),
            sensitive_values=(invite_secret, plaintext_token),
        )
        return self._object(result)

    def invite_status(self, invite_id: str) -> JsonObject:
        path = f"/v1/invites/{_segment(invite_id, 'invite_id')}/status"
        return self._object(self._request("GET", path))

    # Natural-language alias retained for callers that prefer verb-first APIs.
    get_invite_status = invite_status

    def get_invite(self, vault_id: str, invite_id: str) -> JsonObject:
        path = (
            f"/v1/vaults/{_segment(vault_id, 'vault_id')}/invites/"
            f"{_segment(invite_id, 'invite_id')}"
        )
        return self._object(self._request("GET", path))

    def approve_invite(
        self,
        vault_id: str,
        invite_id: str,
        *,
        wrapped_vault_key: str,
        membership_statement: str,
        membership_signature: str,
    ) -> JsonObject:
        """Approve an invite without interpreting the wrapped vault key."""
        if not all(
            isinstance(value, str)
            for value in (wrapped_vault_key, membership_statement, membership_signature)
        ):
            raise VpsValidationError("invite approval evidence must be canonical JSON text")
        path = (
            f"/v1/vaults/{_segment(vault_id, 'vault_id')}/invites/"
            f"{_segment(invite_id, 'invite_id')}/approve"
        )
        result = self._request(
            "POST",
            path,
            payload={
                "wrapped_vault_key": wrapped_vault_key,
                "membership_statement": membership_statement,
                "membership_signature": membership_signature,
            },
            expected_statuses=(200, 201),
            sensitive_values=_opaque_strings(wrapped_vault_key),
        )
        return self._object(result)
