"""In-memory secret backend and entry helpers for synthetic vault tests."""
from __future__ import annotations

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.models import Entry, EntryType


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


def add_entry(dev, name, secret, *, type=EntryType.API_KEY):
    e = Entry.new(name=name, type=type, fields={"secret_body": True} if type == EntryType.NOTE else {})
    dev.store.add(e)
    dev.backend.set(e.id, secret)
    return e
