"""WebVault credential loading must be strictly non-interactive."""

from keys_keeper.backend import Sealed
from keys_keeper.composition import AccessContext
from keys_keeper.config import SyncConfig, save_sync_config
from keys_keeper.webvault.remote import load_s3_base


def test_local_sync_credentials_use_ui_forbidden_context(kk_home, monkeypatch):
    save_sync_config(
        SyncConfig(
            mode="manual",
            endpoint="https://s3.example.com",
            bucket="vault",
            prefix="keys-keeper",
        ).with_device_id()
    )
    captured = {}

    class FakeBackend:
        def get(self, account):
            return Sealed("test-access" if account.endswith("access-key-id") else "test-secret")

    def fake_build_backend(*, access):
        captured["access"] = access
        return FakeBackend()

    monkeypatch.setattr("keys_keeper.composition.build_backend", fake_build_backend)
    base = load_s3_base()

    assert base.access_key_id == "test-access"
    assert isinstance(base.secret_key, Sealed)
    assert captured["access"] is AccessContext.UI_FORBIDDEN
