"""Build the proxy's S3 access from env (deploy) or the local `keys sync` config
(dev/demo). The proxy holds the S3 credentials and signs requests server-side;
they never reach the browser. This module reuses S3Remote/S3Signer verbatim and
imports NOTHING from crypto — the proxy only ever forwards ciphertext bytes."""
from __future__ import annotations

import os
from dataclasses import dataclass

from keys_keeper.backend import Sealed
from keys_keeper.sync_remote import S3Remote, S3Signer


@dataclass
class S3Base:
    endpoint: str
    bucket: str
    region: str
    addressing: str
    access_key_id: str
    secret_key: Sealed     # stays Sealed until the SigV4 HMAC, server-side only


def load_s3_base() -> S3Base:
    """Env (WEBVAULT_S3_*) wins; else fall back to the local `keys sync` config +
    keychain creds so a self-hosting user can demo against their existing bucket."""
    if os.environ.get("WEBVAULT_S3_ENDPOINT"):
        return S3Base(
            endpoint=os.environ["WEBVAULT_S3_ENDPOINT"],
            bucket=os.environ["WEBVAULT_S3_BUCKET"],
            region=os.environ.get("WEBVAULT_S3_REGION", "us-east-1"),
            addressing=os.environ.get("WEBVAULT_S3_ADDRESSING", "path"),
            access_key_id=os.environ["WEBVAULT_S3_ACCESS_KEY_ID"],
            secret_key=Sealed(os.environ["WEBVAULT_S3_SECRET_KEY"]),
        )
    from keys_keeper.cli_sync import SYNC_ACCESS, SYNC_SECRET
    from keys_keeper.composition import AccessContext, build_backend
    from keys_keeper.config import load_sync_config
    from keys_keeper.paths import Paths
    cfg = load_sync_config(Paths())
    if not cfg.endpoint or not cfg.bucket:
        raise RuntimeError(
            "no S3 config — set WEBVAULT_S3_* env vars or run `keys sync setup`")
    # A long-running server must never inherit the user's interactive prompt
    # preference. Missing or inaccessible original Keychain items fail closed.
    backend = build_backend(access=AccessContext.UI_FORBIDDEN)
    return S3Base(
        endpoint=cfg.endpoint, bucket=cfg.bucket, region=cfg.region,
        addressing=cfg.addressing,
        access_key_id=backend.get(SYNC_ACCESS).unseal(),
        secret_key=backend.get(SYNC_SECRET),
    )


def remote_for(base: S3Base, prefix: str) -> S3Remote:
    """An S3Remote scoped to one account's prefix. The prefix comes from the
    server-side account record (the session uid), never from the request."""
    signer = S3Signer(base.access_key_id, base.secret_key, region=base.region)
    return S3Remote(signer=signer, endpoint=base.endpoint, bucket=base.bucket,
                    prefix=prefix, addressing=base.addressing)


def default_base_prefix() -> str:
    """The single-tenant vault prefix (so the web reads the same vault the CLI
    syncs). Multi-tenant mode overrides this with tenants/<uid>/."""
    env = os.environ.get("WEBVAULT_VAULT_PREFIX")
    if env:
        return env.strip("/")
    try:
        from keys_keeper.config import load_sync_config
        from keys_keeper.paths import Paths
        return (load_sync_config(Paths()).prefix or "keys-keeper").strip("/")
    except Exception:
        return "keys-keeper"
