"""Phase 1 — config.py: non-secret [sync] settings, hand-rolled flat TOML."""
import sys
import pytest

from keys_keeper.paths import Paths
from keys_keeper.config import (
    SyncConfig, SyncConfigError, load_sync_config, save_sync_config, set_mode,
)


def test_F3_missing_file_returns_defaults_and_does_not_create(kk_home):
    paths = Paths()
    cfg = load_sync_config(paths)
    assert cfg.mode == "off"
    assert cfg.region == "us-east-1"
    assert cfg.addressing == "path"
    assert cfg.retain_snapshots == 20
    assert not paths.config_toml.exists()  # F3: no file written on read


def test_F2_roundtrip_types(kk_home):
    paths = Paths()
    cfg = SyncConfig(
        mode="manual", endpoint="https://s3.example.com", bucket="b",
        region="auto", prefix="kk", device_id="mac-abcd1234",
        addressing="path", retain_snapshots=5,
    )
    save_sync_config(cfg, paths)
    got = load_sync_config(paths)
    assert got == cfg
    assert isinstance(got.retain_snapshots, int)


def test_F2_unknown_mode_and_addressing_rejected(kk_home):
    with pytest.raises(SyncConfigError):
        SyncConfig(mode="sideways").validate()
    with pytest.raises(SyncConfigError):
        SyncConfig(addressing="weird", mode="off").validate()
    with pytest.raises(SyncConfigError):
        SyncConfig(retain_snapshots=0, mode="off").validate()


def test_proxy_defaults_to_direct_and_roundtrips(kk_home):
    paths = Paths()
    assert SyncConfig().proxy == "direct"            # secrets backups bypass the OS proxy
    cfg = SyncConfig(mode="manual", endpoint="https://s3.example.com", bucket="b",
                     proxy="http://127.0.0.1:1082")
    save_sync_config(cfg, paths)
    assert load_sync_config(paths).proxy == "http://127.0.0.1:1082"


def test_proxy_rejects_garbage_but_allows_direct_system_url(kk_home):
    for ok in ("direct", "system", "http://p:8080", "https://p:8080"):
        SyncConfig(mode="off", proxy=ok).validate()  # no raise
    with pytest.raises(SyncConfigError):
        SyncConfig(mode="off", proxy="socks5://nope").validate()


def test_F4_device_id_generated_once_and_stable(kk_home):
    paths = Paths()
    cfg = SyncConfig(mode="manual", endpoint="https://s3.example.com", bucket="b").with_device_id()
    assert cfg.device_id
    assert all(c.isalnum() or c in "._-" for c in cfg.device_id)
    save_sync_config(cfg, paths)
    a = load_sync_config(paths).device_id
    b = load_sync_config(paths).device_id
    assert a == b == cfg.device_id


def test_F5_no_secret_literals_in_file(kk_home):
    paths = Paths()
    cfg = SyncConfig(mode="manual", endpoint="https://s3.example.com", bucket="b",
                     device_id="d1").with_device_id()
    save_sync_config(cfg, paths)
    blob = paths.config_toml.read_text()
    # config never holds these; assert they cannot be there
    for secret in ("AKIAEXAMPLE", "wJalrXUtnFEMI", "my-passphrase"):
        assert secret not in blob


def test_S8_http_nonloopback_refused_https_ok_loopback_ok(kk_home):
    with pytest.raises(SyncConfigError):
        SyncConfig(mode="manual", endpoint="http://s3.example.com", bucket="b").validate()
    # https is fine
    SyncConfig(mode="manual", endpoint="https://s3.example.com", bucket="b").validate()
    # loopback http is allowed (local MinIO dev)
    SyncConfig(mode="manual", endpoint="http://127.0.0.1:9000", bucket="b").validate()
    # explicit override allowed
    SyncConfig(mode="manual", endpoint="http://s3.example.com", bucket="b", insecure=True).validate()


def test_S10_unsafe_prefix_rejected(kk_home):
    with pytest.raises(SyncConfigError):
        SyncConfig(mode="off", prefix="/abs").validate()
    with pytest.raises(SyncConfigError):
        SyncConfig(mode="off", prefix="a/../b").validate()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX perms")
def test_S11_config_file_is_owner_only(kk_home):
    paths = Paths()
    save_sync_config(SyncConfig(mode="off"), paths)
    mode = paths.config_toml.stat().st_mode & 0o077
    assert mode == 0, f"config.toml is group/other-accessible: {oct(mode)}"


def test_set_mode_persists(kk_home):
    paths = Paths()
    save_sync_config(SyncConfig(mode="manual", endpoint="https://s3.example.com", bucket="b"), paths)
    set_mode("auto", paths)
    assert load_sync_config(paths).mode == "auto"


def test_comments_and_quotes_parse(kk_home):
    paths = Paths()
    paths.ensure()
    paths.config_toml.write_text(
        '# header\n[sync]\nmode = "manual"  # trailing\n'
        'endpoint = "https://s3.example.com"\nbucket = "b"\nretain_snapshots = 7\n'
    )
    cfg = load_sync_config(paths)
    assert cfg.mode == "manual"
    assert cfg.retain_snapshots == 7
    assert cfg.bucket == "b"
