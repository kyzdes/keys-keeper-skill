"""Legacy migration preserves the first lossless backup and refuses unsafe IO."""
import json
import os

import pytest

from keys_keeper import store as module
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore, StoreError


@pytest.fixture
def legacy(tmp_path):
    paths = Paths(tmp_path / "legacy")
    paths.ensure()
    original = b'{\n  "schema_version": 2,\n  "entries": [], "tombstones": []\n}\n'
    paths.data_json.write_bytes(original)
    paths.data_json.chmod(0o644)
    return paths, MetadataStore(paths), original, paths.root / "data.v2.json.bak"


def test_first_backup_preserves_exact_legacy_0644_bytes_without_rewriting_on_reentry(legacy):
    paths, store, original, backup = legacy
    store.migrate_catalog_v3()
    assert backup.read_bytes() == original
    assert json.loads(paths.data_json.read_bytes())["schema_version"] == 3
    before = backup.stat()
    store.migrate_catalog_v3()
    after = backup.stat()
    assert backup.read_bytes() == original
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)


def test_existing_regular_legacy_backup_is_preserved_without_overwrite(legacy):
    _, store, _, backup = legacy
    first = b"exact original historical backup bytes"
    backup.write_bytes(first)
    backup.chmod(0o644)
    before = backup.stat()
    store.migrate_catalog_v3()
    after = backup.stat()
    assert backup.read_bytes() == first
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)


@pytest.mark.parametrize("dangling", [False, True])
def test_migration_symlink_destination_never_changes_external_target_or_metadata(legacy, tmp_path, dangling):
    paths, store, original, backup = legacy
    external = tmp_path / "external-target"
    if not dangling:
        external.write_bytes(b"protected external bytes")
    try:
        backup.symlink_to(external)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(StoreError, match="migration backup unavailable"):
        store.migrate_catalog_v3()
    assert paths.data_json.read_bytes() == original
    assert backup.is_symlink()
    if dangling:
        assert not external.exists()
    else:
        assert external.read_bytes() == b"protected external bytes"


@pytest.mark.parametrize("target", ["source", "backup"])
@pytest.mark.parametrize("kind", ["oversized", "fifo", "directory"])
def test_migration_rejects_oversized_or_special_file_before_read(legacy, monkeypatch, target, kind):
    paths, store, original, backup = legacy
    unsafe = paths.data_json if target == "source" else backup
    if unsafe.exists():
        unsafe.unlink()
    if kind == "oversized":
        unsafe.write_bytes(b"x" * 129)
        monkeypatch.setattr(module, "_MAX_METADATA_BYTES", 128)
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO unavailable")
        os.mkfifo(unsafe, 0o600)
    else:
        unsafe.mkdir()
    unsafe_inode = unsafe.stat().st_ino
    real_read = os.read

    def no_unsafe_read(fd, size):
        if os.fstat(fd).st_ino == unsafe_inode:
            pytest.fail("unsafe migration file read")
        return real_read(fd, size)

    monkeypatch.setattr(os, "read", no_unsafe_read)
    with pytest.raises(StoreError):
        store.migrate_catalog_v3()
    if target == "backup":
        assert paths.data_json.read_bytes() == original
    else:
        assert not backup.exists()


def test_backup_created_between_validation_and_publication_remains_first(legacy, monkeypatch):
    paths, store, _, backup = legacy
    first = b"concurrently created first backup"
    real_read = module._secure_read
    reads = []

    def competing_writer(path, **kwargs):
        result = real_read(path, **kwargs)
        if path == paths.data_json:
            reads.append(True)
            if len(reads) == 2:
                backup.write_bytes(first)
        return result

    monkeypatch.setattr(module, "_secure_read", competing_writer)
    store.migrate_catalog_v3()
    assert backup.read_bytes() == first
    assert len(reads) >= 2
    assert json.loads(paths.data_json.read_bytes())["schema_version"] == 3
