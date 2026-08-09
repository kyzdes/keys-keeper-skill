"""Known-answer test: the browser WebCrypto port (kkcrypto.mjs) decrypts a blob
produced by the Python CLI crypto, byte-identically, and its auth-hash derivation
matches a server-side PBKDF2. Runs under Node; skipped if node is absent."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from keys_keeper.crypto import encrypt_blob

ROOT = Path(__file__).resolve().parent.parent
KKCRYPTO = ROOT / "src" / "keys_keeper" / "webvault" / "static" / "kkcrypto.mjs"
HARNESS = Path(__file__).parent / "webvault_crypto_harness.mjs"

_NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(_NODE is None, reason="node not installed")


def _run(blob_path, passphrase, auth_salt_hex, iters):
    return subprocess.run(
        [_NODE, str(HARNESS), str(KKCRYPTO), str(blob_path), passphrase,
         auth_salt_hex, str(iters)],
        capture_output=True, text=True, encoding="utf-8", errors="strict",
        timeout=120,
    )


def test_webcrypto_decrypts_cli_produced_blob(tmp_path):
    payload = {
        "schema_version": 2,
        "entries": [{
            "id": "kk:abc", "name": "demo", "type": "api_key", "fields": {"k": "v"},
            "tags": ["x"], "note": "пароль 🔑", "refs": [],
            "created_at": "2026-06-04T00:00:00Z", "updated_at": "2026-06-04T00:00:00Z",
            "_secret": "sk-SENSITIVE-123", "_secret_passphrase": None,
        }],
        "tombstones": [{"id": "kk:dead", "name": "old", "deleted_at": "2026-06-03T00:00:00Z"}],
    }
    pw = "correct horse battery staple"
    blob = encrypt_blob(json.dumps(payload).encode("utf-8"), password=pw)
    bp = tmp_path / "vault.kk"
    bp.write_bytes(blob)

    auth_salt = bytes(range(1, 17))           # 16 bytes
    iters = 200_000
    expected_ah = hashlib.pbkdf2_hmac("sha256", pw.encode(), auth_salt, iters, 32).hex()

    r = _run(bp, pw, auth_salt.hex(), iters)
    assert r.returncode == 0, r.stderr
    res = json.loads(r.stdout)
    assert res["payload"] == payload          # byte-identical decrypt round-trip
    assert res["ah"] == expected_ah           # auth-hash derivation == server's


def test_webcrypto_wrong_passphrase_is_rejected(tmp_path):
    blob = encrypt_blob(b'{"entries":[],"tombstones":[]}', password="right-one")
    bp = tmp_path / "vault.kk"
    bp.write_bytes(blob)
    r = _run(bp, "wrong-one", "00" * 16, 1000)
    assert r.returncode != 0                  # GCM tag fails -> BadPassword thrown
    assert "BadPassword" in r.stderr or "passphrase incorrect" in r.stderr
