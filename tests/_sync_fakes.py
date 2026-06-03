"""In-memory fakes for offline sync-engine tests."""
from __future__ import annotations
from types import SimpleNamespace

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore
from keys_keeper.sync import SyncEngine
from keys_keeper.sync_remote import NotFound, PreconditionFailed


class FakeRemote:
    """In-memory RemoteStore. Keys are exactly what the engine passes
    (no S3 prefix). Honours If-None-Match:* (real CAS)."""

    def __init__(self):
        self.objs: dict[str, bytes] = {}
        self.put_log: list[str] = []

    def put_object(self, key, body, *, if_none_match=None, content_type=None):
        if if_none_match == "*" and key in self.objs:
            raise PreconditionFailed(key)
        self.objs[key] = bytes(body)
        self.put_log.append(key)
        return '"etag"'

    def get_object(self, key):
        if key not in self.objs:
            raise NotFound(key)
        return self.objs[key]

    def head_object(self, key):
        return {"ETag": '"x"'} if key in self.objs else None

    def list_objects(self, prefix):
        return [k for k in self.objs if k.startswith(prefix)]

    def delete_object(self, key):
        self.objs.pop(key, None)

    def probe_cas(self):
        return True  # FakeRemote honours If-None-Match:* (real CAS)


class RaceOnceRemote(FakeRemote):
    """Simulates one lost CAS race: just before the first conditional commit to
    a versions/ key, an `on_first_commit` callback lets a *real* peer commit that
    same version first (a valid snapshot+commit), so our PUT then fails 412 and
    the engine must re-pull, re-merge, and retry."""

    def __init__(self):
        super().__init__()
        self.on_first_commit = None
        self._fired = False

    def put_object(self, key, body, *, if_none_match=None, content_type=None):
        if (if_none_match == "*" and key.startswith("versions/")
                and not self._fired and self.on_first_commit is not None):
            self._fired = True
            self.on_first_commit()  # peer commits this version first (valid)
        return super().put_object(key, body, if_none_match=if_none_match)


class NonCasRemote(FakeRemote):
    """A provider that IGNORES If-None-Match (overwrites unconditionally) —
    models older MinIO / B2. The engine must fall back to read-back-after-write."""

    def put_object(self, key, body, *, if_none_match=None, content_type=None):
        self.objs[key] = bytes(body)
        self.put_log.append(key)
        return '"etag"'

    def probe_cas(self):
        return False


class FakeBackend(KeychainBackend):
    def __init__(self, fail_after: int | None = None):
        self.d: dict[str, str] = {}
        self._fail_after = fail_after
        self._sets = 0

    def get(self, account):
        if account not in self.d:
            raise KeychainError(account)
        return Sealed(self.d[account])

    def set(self, account, value):
        self._sets += 1
        if self._fail_after is not None and self._sets > self._fail_after:
            raise KeychainError(f"simulated keychain failure on set #{self._sets}")
        self.d[account] = value

    def delete(self, account):
        self.d.pop(account, None)

    def list_ids(self):
        return list(self.d)


def make_device(remote, tmp_path, name, *, device_id=None, retain=20, backend=None,
                cas=True):
    paths = Paths(root=tmp_path / name)
    paths.ensure()
    store = MetadataStore(paths)
    backend = backend or FakeBackend()
    engine = SyncEngine(remote=remote, store=store, backend=backend,
                        device_id=device_id or name, retain_snapshots=retain,
                        paths=paths, cas_supported=cas)
    return SimpleNamespace(name=name, paths=paths, store=store,
                           backend=backend, engine=engine)


def add_entry(dev, name, secret, *, type=EntryType.API_KEY):
    e = Entry.new(name=name, type=type, fields={"_": "x"} if type == EntryType.NOTE else {})
    dev.store.add(e)
    dev.backend.set(e.id, secret)
    return e


def live_ids(dev):
    return {e.id for e in dev.store.list()}


def names(dev):
    return sorted(e.name for e in dev.store.list())
