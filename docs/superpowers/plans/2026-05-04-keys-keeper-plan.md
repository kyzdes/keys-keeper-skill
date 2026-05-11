# keys-keeper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a personal macOS-first secrets manager — CLI (`keys`) + local web admin + Claude skill — with hard architectural guarantees that secret values never leak into agent transcripts.

**Architecture:** Python 3.10+ package, pipx-installable. Two-layer storage (macOS Keychain for secrets, JSON file for metadata). Output-safe command surface. Localhost-only web admin with token auth, served from the same Python process via stdlib `http.server` + Jinja2 templates + vanilla JS.

**Tech Stack:** Python 3.10+ · stdlib (`subprocess`, `argparse`, `http.server`, `fcntl`, `tempfile`, `secrets`, `hashlib`, `json`) · `jinja2` · `cryptography` (AES-GCM + PBKDF2) · pytest for tests · macOS `security` CLI for Keychain access.

---

## Source documents

- **Design doc:** `docs/superpowers/specs/2026-05-04-keys-keeper-design.md`
- **UX spec (locked variants):** `ux-spec-2026-05-04-keys-keeper-admin.md`
- **Visual reference (interactive canvas):** `keys-keeper-admin-canvas.html`

## File structure

```
keys-keeper-skill/
├── pyproject.toml                       # pipx-installable, entry: keys = keys_keeper.cli:main
├── README.md                            # install + usage (Phase 7)
├── src/keys_keeper/
│   ├── __init__.py                      # __version__ = "0.1.0"
│   ├── __main__.py                      # python -m keys_keeper → cli.main()
│   ├── cli.py                           # argparse routing, top-level main()
│   ├── paths.py                         # XDG paths, file locations
│   ├── models.py                        # Entry dataclass, EntryType, validation
│   ├── backend.py                       # KeychainBackend abstract + MacOSKeychainBackend
│   ├── store.py                         # MetadataStore (data.json, flock, atomic write)
│   ├── audit.py                         # AuditLog (jsonl, monthly rotation)
│   ├── refs.py                          # ref resolution + cycle detection
│   ├── parser.py                        # bulk paste parser
│   ├── crypto.py                        # AES-GCM export/import
│   ├── ssh_runner.py                    # keys ssh tempfile + exec
│   ├── server.py                        # HTTP server + token auth + auto-shutdown
│   ├── api.py                           # JSON API handlers
│   ├── pages.py                         # HTML page handlers (Jinja2 dispatch)
│   ├── templates/                       # Jinja2 templates
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── entry_detail.html
│   │   ├── new_edit.html
│   │   ├── bulk_paste.html
│   │   ├── audit.html
│   │   └── settings.html
│   └── static/
│       ├── app.css                      # ported from canvas: locked variants only
│       ├── app.js                       # vanilla JS: search, filters, modals, palette
│       └── tweaks.js                    # tweak toggles for Settings preview
├── tests/
│   ├── conftest.py                      # tmp dir fixture, isolated keychain fixture
│   ├── test_paths.py
│   ├── test_models.py
│   ├── test_backend.py
│   ├── test_store.py
│   ├── test_audit.py
│   ├── test_refs.py
│   ├── test_parser.py
│   ├── test_crypto.py
│   ├── test_cli_add.py
│   ├── test_cli_read.py                 # list/info/reveal
│   ├── test_cli_copy_inject.py
│   ├── test_cli_edit_rm.py
│   ├── test_cli_ssh.py
│   ├── test_cli_export.py
│   ├── test_cli_doctor.py
│   ├── test_server_auth.py
│   ├── test_server_api.py
│   ├── test_server_pages.py
│   └── test_e2e_admin.py
├── skills/keys-keeper/
│   ├── SKILL.md                         # text drafted in design doc §4
│   └── references/
│       └── examples.md                  # worked examples for Claude
└── scripts/
    └── install_skill.sh                 # cp skills to ~/.claude/skills/
```

---

## Phase 1 — CLI core

### Task 1.1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/keys_keeper/__init__.py`
- Create: `src/keys_keeper/__main__.py`
- Create: `src/keys_keeper/paths.py`
- Create: `tests/conftest.py`
- Create: `tests/test_paths.py`
- Create: `.gitignore`

- [ ] **Step 1: Write `.gitignore`**

```
__pycache__/
*.py[cod]
*.egg-info/
.pytest_cache/
.venv/
venv/
build/
dist/
.coverage
htmlcov/
.DS_Store
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "keys-keeper"
version = "0.1.0"
description = "Personal macOS secrets manager — CLI + local admin + Claude skill"
requires-python = ">=3.10"
authors = [{name = "kuzdes"}]
dependencies = [
    "jinja2>=3.1",
    "cryptography>=41.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4",
    "pytest-cov>=4.1",
]

[project.scripts]
keys = "keys_keeper.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/keys_keeper"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --strict-markers"
```

- [ ] **Step 3: Write `src/keys_keeper/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 4: Write `src/keys_keeper/__main__.py`**

```python
from keys_keeper.cli import main

if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Write the failing test for `paths.py`**

`tests/test_paths.py`:

```python
import os
from pathlib import Path
from keys_keeper.paths import Paths


def test_paths_default_uses_xdg_config_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.delenv("KEYS_KEEPER_HOME", raising=False)
    p = Paths()
    assert p.root == tmp_path / ".config" / "keys-keeper"
    assert p.data_json == p.root / "data.json"
    assert p.audit_jsonl == p.root / "audit.jsonl"
    assert p.config_toml == p.root / "config.toml"


def test_paths_respects_keys_keeper_home_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom-kk"
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(custom))
    p = Paths()
    assert p.root == custom


def test_paths_ensure_creates_directories(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    p = Paths()
    assert not p.root.exists()
    p.ensure()
    assert p.root.exists()
    assert p.root.is_dir()
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `pytest tests/test_paths.py -v`
Expected: ImportError or ModuleNotFoundError on `keys_keeper.paths`.

- [ ] **Step 7: Write `src/keys_keeper/paths.py`**

```python
"""Filesystem paths for keys-keeper config + data."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_root() -> Path:
    if env := os.environ.get("KEYS_KEEPER_HOME"):
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "keys-keeper"


@dataclass
class Paths:
    root: Path = field(default_factory=_default_root)

    @property
    def data_json(self) -> Path:
        return self.root / "data.json"

    @property
    def data_json_bak(self) -> Path:
        return self.root / "data.json.bak"

    @property
    def audit_jsonl(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def config_toml(self) -> Path:
        return self.root / "config.toml"

    def audit_archive(self, year_month: str) -> Path:
        return self.root / f"audit.{year_month}.jsonl.gz"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 8: Run tests and confirm they pass**

Run: `pytest tests/test_paths.py -v`
Expected: 3 passed.

- [ ] **Step 9: Write `tests/conftest.py`**

```python
"""Shared pytest fixtures for keys-keeper."""
import os
import subprocess
from pathlib import Path
import pytest


@pytest.fixture
def kk_home(tmp_path, monkeypatch):
    """Isolated KEYS_KEEPER_HOME for each test."""
    home = tmp_path / "kk-home"
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(home))
    return home


@pytest.fixture
def test_keychain(tmp_path):
    """Create an isolated macOS keychain for testing.

    Returns the keychain path. Caller is responsible for setting
    `KEYS_KEEPER_TEST_KEYCHAIN` env var if the backend reads it,
    or for passing it explicitly to the backend constructor.
    """
    if os.uname().sysname != "Darwin":
        pytest.skip("macOS keychain tests require Darwin")
    kc_path = tmp_path / "test.keychain-db"
    pwd = "test-pwd"
    subprocess.run(
        ["security", "create-keychain", "-p", pwd, str(kc_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["security", "unlock-keychain", "-p", pwd, str(kc_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["security", "set-keychain-settings", "-u", str(kc_path)],
        check=True, capture_output=True,
    )
    yield kc_path
    subprocess.run(["security", "delete-keychain", str(kc_path)], capture_output=True)
```

- [ ] **Step 10: Verify project installs in editable mode**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
keys --help 2>&1 | head -3 || echo "expected: keys not yet implemented"
pytest -q
```

Expected: `pip install -e` succeeds; `pytest` runs paths tests successfully (CLI not yet impl, that's fine).

- [ ] **Step 11: Commit**

```bash
git add .gitignore pyproject.toml src/ tests/
git commit -m "feat: project scaffolding + paths module"
```

### Task 1.2: Models — Entry dataclass + EntryType + validation

**Files:**
- Create: `src/keys_keeper/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:

```python
import pytest
from datetime import datetime, timezone
from keys_keeper.models import Entry, EntryType, ValidationError, validate_name


def test_validate_name_accepts_valid_slug():
    validate_name("openrouter-cline")
    validate_name("do-prod-droplet")
    validate_name("mysite.com")
    validate_name("stripe_test")


def test_validate_name_rejects_invalid():
    with pytest.raises(ValidationError, match="length"):
        validate_name("a")
    with pytest.raises(ValidationError, match="length"):
        validate_name("x" * 65)
    with pytest.raises(ValidationError, match="characters"):
        validate_name("Has Space")
    with pytest.raises(ValidationError, match="characters"):
        validate_name("UPPER")
    with pytest.raises(ValidationError, match="characters"):
        validate_name("-leading-dash")
    with pytest.raises(ValidationError, match="characters"):
        validate_name("trailing-dash-")


def test_entry_type_enum():
    assert EntryType.API_KEY.value == "api_key"
    assert EntryType.SSH_KEY.value == "ssh_key"
    assert EntryType.SERVER.value == "server"
    assert EntryType.DOMAIN.value == "domain"
    assert EntryType.NOTE.value == "note"


def test_entry_minimal_construction():
    e = Entry(
        id="kk:abc",
        name="openrouter-cline",
        type=EntryType.API_KEY,
        fields={"service": "openrouter"},
        tags=["llm"],
        note="",
        refs=[],
        created_at="2026-05-04T10:00:00Z",
        updated_at="2026-05-04T10:00:00Z",
    )
    assert e.name == "openrouter-cline"
    assert e.type is EntryType.API_KEY


def test_entry_to_dict_round_trip():
    e = Entry(
        id="kk:abc",
        name="do-prod",
        type=EntryType.SERVER,
        fields={"host": "1.2.3.4", "port": 22, "user": "root", "auth": "ssh_key"},
        tags=["prod"],
        note="main",
        refs=[{"role": "ssh_key", "name": "my-do-key"}],
        created_at="2026-05-04T10:00:00Z",
        updated_at="2026-05-04T10:00:00Z",
    )
    d = e.to_dict()
    assert d["type"] == "server"
    assert d["refs"][0]["role"] == "ssh_key"
    e2 = Entry.from_dict(d)
    assert e2 == e


def test_entry_validates_fields_for_type():
    # api_key: service is optional, no other required fields
    Entry.new(name="x-test", type=EntryType.API_KEY, fields={})
    # server: requires host, user, auth
    with pytest.raises(ValidationError, match="host"):
        Entry.new(name="bad-server", type=EntryType.SERVER, fields={})
    # ssh_key: requires public_key
    with pytest.raises(ValidationError, match="public_key"):
        Entry.new(name="bad-ssh", type=EntryType.SSH_KEY, fields={})
    # domain: requires host
    with pytest.raises(ValidationError, match="host"):
        Entry.new(name="bad-dom", type=EntryType.DOMAIN, fields={})
    # note: requires secret_body flag
    Entry.new(name="ok-note", type=EntryType.NOTE, fields={"secret_body": False, "body": "hi"})


def test_entry_new_assigns_uuid_and_timestamps():
    e = Entry.new(name="test-key", type=EntryType.API_KEY, fields={})
    assert e.id.startswith("kk:")
    assert len(e.id) > 10
    assert e.created_at == e.updated_at
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: ImportError on `keys_keeper.models`.

- [ ] **Step 3: Write `src/keys_keeper/models.py`**

```python
"""Domain models: Entry, EntryType, validation."""
from __future__ import annotations
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ValidationError(ValueError):
    """Raised for invalid entry data."""


class EntryType(str, Enum):
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    SERVER = "server"
    DOMAIN = "domain"
    NOTE = "note"


_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$")


def validate_name(name: str) -> None:
    if not isinstance(name, str):
        raise ValidationError("name must be a string")
    if not (2 <= len(name) <= 64):
        raise ValidationError(f"name length must be 2-64 (got {len(name)})")
    if not _NAME_RE.fullmatch(name):
        raise ValidationError(
            "name contains invalid characters; allowed: lowercase a-z, 0-9, dot, dash, underscore; "
            "must start and end with alphanumeric"
        )


_REQUIRED_FIELDS: dict[EntryType, set[str]] = {
    EntryType.API_KEY: set(),
    EntryType.SSH_KEY: {"public_key"},
    EntryType.SERVER: {"host", "user", "auth"},
    EntryType.DOMAIN: {"host"},
    EntryType.NOTE: {"secret_body"},
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Entry:
    id: str
    name: str
    type: EntryType
    fields: dict[str, Any]
    tags: list[str]
    note: str
    refs: list[dict[str, str]]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "fields": self.fields,
            "tags": self.tags,
            "note": self.note,
            "refs": self.refs,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Entry:
        return cls(
            id=d["id"],
            name=d["name"],
            type=EntryType(d["type"]),
            fields=dict(d.get("fields", {})),
            tags=list(d.get("tags", [])),
            note=d.get("note", ""),
            refs=list(d.get("refs", [])),
            created_at=d["created_at"],
            updated_at=d["updated_at"],
        )

    @classmethod
    def new(
        cls,
        *,
        name: str,
        type: EntryType,
        fields: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        note: str = "",
        refs: list[dict[str, str]] | None = None,
    ) -> Entry:
        validate_name(name)
        f = dict(fields or {})
        missing = _REQUIRED_FIELDS[type] - set(f)
        if missing:
            raise ValidationError(
                f"{type.value} requires fields: {sorted(missing)} (have: {sorted(f)})"
            )
        now = _now_iso()
        return cls(
            id=f"kk:{uuid.uuid4()}",
            name=name,
            type=type,
            fields=f,
            tags=list(tags or []),
            note=note,
            refs=list(refs or []),
            created_at=now,
            updated_at=now,
        )
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_models.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/models.py tests/test_models.py
git commit -m "feat: Entry dataclass with type-specific field validation"
```

### Task 1.3: KeychainBackend — abstract + macOS impl

**Files:**
- Create: `src/keys_keeper/backend.py`
- Create: `tests/test_backend.py`

- [ ] **Step 1: Write the failing test**

`tests/test_backend.py`:

```python
import os
import pytest
from keys_keeper.backend import (
    KeychainBackend,
    MacOSKeychainBackend,
    KeychainError,
)


@pytest.fixture
def backend(test_keychain):
    return MacOSKeychainBackend(
        service="keys-keeper-test",
        keychain_path=str(test_keychain),
    )


def test_set_and_get_round_trip(backend):
    backend.set("kk:abc", "sk-test-secret")
    assert backend.get("kk:abc") == "sk-test-secret"


def test_get_missing_raises(backend):
    with pytest.raises(KeychainError, match="not found"):
        backend.get("kk:does-not-exist")


def test_set_overwrites_existing(backend):
    backend.set("kk:abc", "first")
    backend.set("kk:abc", "second")
    assert backend.get("kk:abc") == "second"


def test_delete_removes_entry(backend):
    backend.set("kk:abc", "x")
    backend.delete("kk:abc")
    with pytest.raises(KeychainError):
        backend.get("kk:abc")


def test_delete_missing_is_noop(backend):
    # idempotent delete
    backend.delete("kk:never-set")  # must not raise


def test_list_ids_returns_only_our_service(backend):
    backend.set("kk:a", "1")
    backend.set("kk:b", "2")
    backend.set("kk:b:passphrase", "p")
    ids = set(backend.list_ids())
    assert ids == {"kk:a", "kk:b", "kk:b:passphrase"}


def test_set_multiline_value(backend):
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nlinetwo\n-----END-----\n"
    backend.set("kk:multi", pem)
    assert backend.get("kk:multi") == pem
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_backend.py -v`
Expected: ImportError on `keys_keeper.backend`.

- [ ] **Step 3: Write `src/keys_keeper/backend.py`**

```python
"""Keychain abstraction. v1 = macOS via `security` CLI."""
from __future__ import annotations
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path


class KeychainError(RuntimeError):
    """Raised when keychain ops fail (not found, access denied, etc)."""


class KeychainBackend(ABC):
    """Storage interface for secret blobs."""

    @abstractmethod
    def get(self, account: str) -> str: ...

    @abstractmethod
    def set(self, account: str, value: str) -> None: ...

    @abstractmethod
    def delete(self, account: str) -> None: ...

    @abstractmethod
    def list_ids(self) -> list[str]: ...


class MacOSKeychainBackend(KeychainBackend):
    """Wraps the macOS `security` CLI.

    All entries belong to one fixed `service` (default: "keys-keeper").
    The `account` is the entry's UUID id (e.g. "kk:abc..." or "kk:abc:passphrase").
    Use a custom `keychain_path` in tests to avoid touching the user's login keychain.
    """

    def __init__(self, *, service: str = "keys-keeper", keychain_path: str | None = None):
        self.service = service
        self.keychain_path = keychain_path

    def _kc_args(self) -> list[str]:
        return [self.keychain_path] if self.keychain_path else []

    def get(self, account: str) -> str:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", self.service, "-a", account, "-w", *self._kc_args()],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise KeychainError(f"keychain entry not found: {account}")
        return result.stdout.rstrip("\n")

    def set(self, account: str, value: str) -> None:
        # delete first to avoid duplicate entries
        self.delete(account)
        result = subprocess.run(
            [
                "security", "add-generic-password",
                "-s", self.service, "-a", account, "-w", value,
                "-U",  # update if exists (belt-and-suspenders)
                *self._kc_args(),
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise KeychainError(f"failed to set keychain entry {account}: {result.stderr.strip()}")

    def delete(self, account: str) -> None:
        subprocess.run(
            ["security", "delete-generic-password", "-s", self.service, "-a", account, *self._kc_args()],
            capture_output=True, text=True,
        )
        # ignore returncode — missing entry is fine

    def list_ids(self) -> list[str]:
        # `security dump-keychain` is heavy + verbose; we use a more targeted approach
        # by parsing `security find-generic-password` repeatedly is impractical too.
        # Instead, dump all generic passwords for our service via dump-keychain.
        result = subprocess.run(
            ["security", "dump-keychain", *self._kc_args()],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return []
        ids: list[str] = []
        current_service = None
        current_account = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('"svce"<blob>='):
                current_service = _extract_attr(line)
            elif line.startswith('"acct"<blob>='):
                current_account = _extract_attr(line)
            elif line.startswith("class:"):
                # next entry starts; flush the previous one
                if current_service == self.service and current_account:
                    ids.append(current_account)
                current_service = None
                current_account = None
        # flush final
        if current_service == self.service and current_account:
            ids.append(current_account)
        return ids


def _extract_attr(line: str) -> str | None:
    # line looks like: "svce"<blob>="keys-keeper-test"
    if '="' in line and line.endswith('"'):
        return line.split('="', 1)[1][:-1]
    return None
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_backend.py -v`
Expected: 7 passed (skipped on non-Darwin).

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/backend.py tests/test_backend.py tests/conftest.py
git commit -m "feat: KeychainBackend abstraction + macOS impl"
```

### Task 1.4: MetadataStore — atomic write, fcntl.flock, schema migration

**Files:**
- Create: `src/keys_keeper/store.py`
- Create: `tests/test_store.py`

- [ ] **Step 1: Write the failing test**

`tests/test_store.py`:

```python
import json
import os
import threading
import time
import pytest
from keys_keeper.models import Entry, EntryType, ValidationError
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore, NameConflict, NotFound, SCHEMA_VERSION


@pytest.fixture
def store(kk_home):
    paths = Paths()
    paths.ensure()
    return MetadataStore(paths)


def test_initial_load_returns_empty_when_no_file(store):
    assert store.list() == []


def test_add_and_list(store):
    e = Entry.new(name="ok-1", type=EntryType.API_KEY, fields={})
    store.add(e)
    listed = store.list()
    assert len(listed) == 1
    assert listed[0].name == "ok-1"


def test_add_persists_to_disk(store, kk_home):
    e = Entry.new(name="ok-2", type=EntryType.API_KEY, fields={})
    store.add(e)
    # New store instance reads from disk
    paths = Paths()
    store2 = MetadataStore(paths)
    assert store2.get_by_name("ok-2") is not None


def test_add_rejects_duplicate_name(store):
    store.add(Entry.new(name="dup", type=EntryType.API_KEY, fields={}))
    with pytest.raises(NameConflict):
        store.add(Entry.new(name="dup", type=EntryType.API_KEY, fields={}))


def test_get_by_name_returns_none_for_missing(store):
    assert store.get_by_name("nope") is None


def test_get_by_name_finds_existing(store):
    store.add(Entry.new(name="findme", type=EntryType.API_KEY, fields={}))
    e = store.get_by_name("findme")
    assert e is not None
    assert e.name == "findme"


def test_update_replaces_entry(store):
    e = Entry.new(name="upd", type=EntryType.API_KEY, fields={})
    store.add(e)
    e.tags = ["new-tag"]
    store.update(e)
    assert store.get_by_name("upd").tags == ["new-tag"]


def test_delete_removes_entry(store):
    store.add(Entry.new(name="del", type=EntryType.API_KEY, fields={}))
    store.delete_by_name("del")
    assert store.get_by_name("del") is None


def test_delete_missing_raises(store):
    with pytest.raises(NotFound):
        store.delete_by_name("never-existed")


def test_atomic_write_creates_backup(store, kk_home):
    e1 = Entry.new(name="first", type=EntryType.API_KEY, fields={})
    store.add(e1)
    e2 = Entry.new(name="second", type=EntryType.API_KEY, fields={})
    store.add(e2)
    paths = Paths()
    assert paths.data_json.exists()
    assert paths.data_json_bak.exists()


def test_schema_version_written(store):
    paths = Paths()
    store.add(Entry.new(name="x-test", type=EntryType.API_KEY, fields={}))
    raw = json.loads(paths.data_json.read_text())
    assert raw["schema_version"] == SCHEMA_VERSION


def test_concurrent_writes_serialize(store, kk_home):
    """Two threads adding different entries must both succeed without losing one."""
    paths = Paths()
    errors = []

    def add_many(prefix: str):
        try:
            local_store = MetadataStore(paths)
            for i in range(5):
                local_store.add(
                    Entry.new(name=f"{prefix}-{i}", type=EntryType.API_KEY, fields={})
                )
        except Exception as ex:
            errors.append(ex)

    t1 = threading.Thread(target=add_many, args=("a",))
    t2 = threading.Thread(target=add_many, args=("b",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert errors == []
    final = MetadataStore(paths)
    names = {e.name for e in final.list()}
    assert names == {f"a-{i}" for i in range(5)} | {f"b-{i}" for i in range(5)}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_store.py -v`
Expected: ImportError on `keys_keeper.store`.

- [ ] **Step 3: Write `src/keys_keeper/store.py`**

```python
"""Metadata store backed by a JSON file with atomic writes + fcntl flock."""
from __future__ import annotations
import fcntl
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Iterator
from contextlib import contextmanager

from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths


SCHEMA_VERSION = 1


class StoreError(RuntimeError):
    pass


class NameConflict(StoreError):
    pass


class NotFound(StoreError):
    pass


class MetadataStore:
    """JSON-backed metadata store. All write ops acquire an exclusive flock
    on a sibling lock file to coordinate cross-process writes.
    """

    def __init__(self, paths: Paths):
        self.paths = paths
        self._lock_path = paths.root / "data.lock"

    # ---------- public API ----------

    def list(self) -> list[Entry]:
        data = self._read()
        return [Entry.from_dict(d) for d in data["entries"]]

    def get_by_name(self, name: str) -> Entry | None:
        for e in self.list():
            if e.name == name:
                return e
        return None

    def get_by_id(self, id_: str) -> Entry | None:
        for e in self.list():
            if e.id == id_:
                return e
        return None

    def add(self, entry: Entry) -> None:
        with self._locked_write() as data:
            for d in data["entries"]:
                if d["name"] == entry.name:
                    raise NameConflict(
                        f"entry with name {entry.name!r} already exists "
                        f"(use --replace to overwrite or --rename to pick a new name)"
                    )
            data["entries"].append(entry.to_dict())

    def update(self, entry: Entry) -> None:
        with self._locked_write() as data:
            for i, d in enumerate(data["entries"]):
                if d["id"] == entry.id:
                    data["entries"][i] = entry.to_dict()
                    return
            raise NotFound(f"no entry with id {entry.id}")

    def replace_by_name(self, entry: Entry) -> None:
        """Used for --replace: overwrites by name even if id differs."""
        with self._locked_write() as data:
            for i, d in enumerate(data["entries"]):
                if d["name"] == entry.name:
                    data["entries"][i] = entry.to_dict()
                    return
            data["entries"].append(entry.to_dict())

    def delete_by_name(self, name: str) -> Entry:
        with self._locked_write() as data:
            for i, d in enumerate(data["entries"]):
                if d["name"] == name:
                    return Entry.from_dict(data["entries"].pop(i))
            raise NotFound(f"no entry with name {name!r}")

    # ---------- internal ----------

    def _read(self) -> dict:
        if not self.paths.data_json.exists():
            return {"schema_version": SCHEMA_VERSION, "entries": []}
        raw = self.paths.data_json.read_text()
        if not raw.strip():
            return {"schema_version": SCHEMA_VERSION, "entries": []}
        data = json.loads(raw)
        sv = data.get("schema_version", 0)
        if sv > SCHEMA_VERSION:
            raise StoreError(
                f"data.json schema_version={sv} is newer than this CLI supports "
                f"({SCHEMA_VERSION}); upgrade keys-keeper"
            )
        if sv < SCHEMA_VERSION:
            data = self._migrate(data, sv)
        return data

    def _migrate(self, data: dict, from_version: int) -> dict:
        # No older versions exist yet; reserved for future schema bumps.
        # Keep a backup on any migration.
        bak = self.paths.root / f"data.v{from_version}.json.bak"
        if self.paths.data_json.exists():
            shutil.copy2(self.paths.data_json, bak)
        data["schema_version"] = SCHEMA_VERSION
        return data

    @contextmanager
    def _locked_write(self) -> Iterator[dict]:
        """Acquire exclusive flock, read, yield mutable dict, write atomically."""
        self.paths.root.mkdir(parents=True, exist_ok=True)
        # Lock on a separate file so we can rename data.json atomically without
        # invalidating the lock fd.
        lock_fd = os.open(self._lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            data = self._read()
            yield data
            self._atomic_write(data)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def _atomic_write(self, data: dict) -> None:
        # Backup the current good file (if any) before overwriting.
        if self.paths.data_json.exists():
            shutil.copy2(self.paths.data_json, self.paths.data_json_bak)
        # Write to temp file in same dir, then rename.
        fd, tmp_path = tempfile.mkstemp(
            dir=self.paths.root, prefix=".data.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2, sort_keys=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.paths.data_json)
        except Exception:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_store.py -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/store.py tests/test_store.py
git commit -m "feat: MetadataStore with atomic write + fcntl flock"
```

### Task 1.5: AuditLog — append-only JSONL with monthly rotation

**Files:**
- Create: `src/keys_keeper/audit.py`
- Create: `tests/test_audit.py`

- [ ] **Step 1: Write the failing test**

`tests/test_audit.py`:

```python
import gzip
import json
import os
import time
from datetime import datetime, timezone
import pytest
from keys_keeper.audit import AuditLog, AuditEvent
from keys_keeper.paths import Paths


@pytest.fixture
def audit(kk_home):
    paths = Paths()
    paths.ensure()
    return AuditLog(paths)


def test_record_appends_event(audit):
    audit.record(op="copy", name="openrouter-cline", id_="kk:abc", success=True)
    events = list(audit.tail(10))
    assert len(events) == 1
    assert events[0]["op"] == "copy"
    assert events[0]["name"] == "openrouter-cline"


def test_record_includes_timestamp_and_caller(audit):
    audit.record(op="inject", name="x", id_="kk:1", file_target="~/proj/.env", success=True)
    e = list(audit.tail(1))[0]
    assert "ts" in e
    assert e["caller_pid"] == os.getppid() or e["caller_pid"] == os.getpid()


def test_jsonl_format_one_event_per_line(audit, kk_home):
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit.record(op="copy", name="b", id_="kk:2", success=True)
    raw = (kk_home / "audit.jsonl").read_text()
    lines = [l for l in raw.splitlines() if l.strip()]
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # each line is valid JSON


def test_filter_by_op(audit):
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit.record(op="inject", name="a", id_="kk:1", success=True)
    audit.record(op="copy", name="b", id_="kk:2", success=True)
    copies = list(audit.search(op="copy"))
    assert len(copies) == 2


def test_filter_by_name(audit):
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit.record(op="copy", name="b", id_="kk:2", success=True)
    a_only = list(audit.search(name="a"))
    assert len(a_only) == 1


def test_rotate_archives_previous_month(audit, kk_home, monkeypatch):
    """When current month differs from latest event's month, rotate."""
    paths = Paths()
    # write a fake old jsonl file
    old_path = paths.audit_jsonl
    old_path.write_text(
        json.dumps({"ts": "2026-04-15T10:00:00Z", "op": "copy", "name": "old", "id": "kk:0", "success": True}) + "\n"
    )
    # set current time to May
    audit.rotate_if_needed(now=datetime(2026, 5, 1, tzinfo=timezone.utc))
    archive = paths.audit_archive("2026-04")
    assert archive.exists()
    with gzip.open(archive, "rt") as f:
        line = f.readline()
        assert "old" in line
    # current jsonl should be empty after rotation
    assert not old_path.exists() or old_path.read_text() == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_audit.py -v`
Expected: ImportError on `keys_keeper.audit`.

- [ ] **Step 3: Write `src/keys_keeper/audit.py`**

```python
"""Append-only audit log (JSONL) with monthly rotation."""
from __future__ import annotations
import gzip
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator
from keys_keeper.paths import Paths


@dataclass
class AuditEvent:
    ts: str
    op: str
    name: str
    id: str
    caller_pid: int
    caller_path: str
    file_target: str | None
    success: bool
    error: str | None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))


def _resolve_caller_path(pid: int) -> str:
    try:
        out = os.popen(f"ps -p {pid} -o command=").read().strip()
        return out or "?"
    except Exception:
        return "?"


class AuditLog:
    def __init__(self, paths: Paths):
        self.paths = paths

    def record(
        self,
        *,
        op: str,
        name: str,
        id_: str,
        file_target: str | None = None,
        success: bool = True,
        error: str | None = None,
    ) -> None:
        self.paths.root.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # parent pid is the caller (CLI was invoked by zsh / claude / etc)
        ppid = os.getppid()
        event = AuditEvent(
            ts=now,
            op=op,
            name=name,
            id=id_,
            caller_pid=ppid,
            caller_path=_resolve_caller_path(ppid),
            file_target=file_target,
            success=success,
            error=error,
        )
        with open(self.paths.audit_jsonl, "a") as f:
            f.write(event.to_json() + "\n")

    def tail(self, n: int = 50) -> Iterator[dict]:
        if not self.paths.audit_jsonl.exists():
            return
        lines = self.paths.audit_jsonl.read_text().splitlines()
        for line in lines[-n:]:
            if line.strip():
                yield json.loads(line)

    def search(
        self,
        *,
        op: str | None = None,
        name: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> Iterator[dict]:
        if not self.paths.audit_jsonl.exists():
            return
        for line in self.paths.audit_jsonl.read_text().splitlines():
            if not line.strip():
                continue
            ev = json.loads(line)
            if op and ev["op"] != op:
                continue
            if name and ev["name"] != name:
                continue
            if since and ev["ts"] < since.strftime("%Y-%m-%dT%H:%M:%SZ"):
                continue
            yield ev
            limit -= 1
            if limit <= 0:
                break

    def rotate_if_needed(self, now: datetime | None = None) -> None:
        """If audit.jsonl contains events from a previous month, archive them."""
        if not self.paths.audit_jsonl.exists():
            return
        now = now or datetime.now(timezone.utc)
        cur_ym = now.strftime("%Y-%m")
        # peek at the first event's month
        with open(self.paths.audit_jsonl) as f:
            first = f.readline().strip()
        if not first:
            return
        first_ev = json.loads(first)
        first_ym = first_ev["ts"][:7]
        if first_ym == cur_ym:
            return
        # archive the entire current file
        archive = self.paths.audit_archive(first_ym)
        with open(self.paths.audit_jsonl, "rb") as src, gzip.open(archive, "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.unlink(self.paths.audit_jsonl)
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_audit.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/audit.py tests/test_audit.py
git commit -m "feat: AuditLog with append + search + monthly rotation"
```

### Task 1.6: CLI scaffold + `add` (with --from-clipboard / --from-file / --stdin) + `list` + `info`

**Files:**
- Create: `src/keys_keeper/cli.py`
- Create: `tests/test_cli_add.py`
- Create: `tests/test_cli_read.py`

- [ ] **Step 1: Write the failing test for `add` and `list`**

`tests/test_cli_add.py`:

```python
import os
import sys
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.backend import MacOSKeychainBackend
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def run(*argv):
    return cli.main(list(argv))


def test_add_from_stdin(cli_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("sk-test-secret\n"))
    rc = run("add", "test-key", "--type", "api_key", "--stdin", "--service", "openrouter")
    assert rc == 0
    paths = Paths()
    store = MetadataStore(paths)
    e = store.get_by_name("test-key")
    assert e is not None
    assert e.fields["service"] == "openrouter"
    backend = MacOSKeychainBackend(
        service=os.environ["KEYS_KEEPER_TEST_SERVICE"],
        keychain_path=os.environ["KEYS_KEEPER_TEST_KEYCHAIN"],
    )
    assert backend.get(e.id) == "sk-test-secret"


def test_add_from_file(cli_env, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-stored-secret")
    rc = run("add", "from-file-key", "--type", "api_key", "--from-file", str(secret_file))
    assert rc == 0
    backend = MacOSKeychainBackend(
        service=os.environ["KEYS_KEEPER_TEST_SERVICE"],
        keychain_path=os.environ["KEYS_KEEPER_TEST_KEYCHAIN"],
    )
    e = MetadataStore(Paths()).get_by_name("from-file-key")
    assert backend.get(e.id) == "file-stored-secret"


def test_add_requires_input_source(cli_env, capsys):
    rc = run("add", "no-source-key", "--type", "api_key")
    assert rc != 0
    out = capsys.readouterr()
    assert "specify" in (out.out + out.err).lower() or "source" in (out.out + out.err).lower()


def test_add_with_tags_and_note(cli_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    run("add", "tagged", "--type", "api_key", "--stdin", "--tag", "llm", "--tag", "personal", "--note", "test note")
    e = MetadataStore(Paths()).get_by_name("tagged")
    assert set(e.tags) == {"llm", "personal"}
    assert e.note == "test note"


def test_add_rejects_duplicate_name(cli_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    run("add", "dupe", "--type", "api_key", "--stdin")
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    rc = run("add", "dupe", "--type", "api_key", "--stdin")
    assert rc != 0
```

`tests/test_cli_read.py`:

```python
import os
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def _seed(monkeypatch, name, type_="api_key", tags=None, note=""):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    args = ["add", name, "--type", type_, "--stdin"]
    if note:
        args += ["--note", note]
    for t in tags or []:
        args += ["--tag", t]
    cli.main(args)


def test_list_empty(cli_env, capsys):
    rc = cli.main(["list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no entries" in out.lower() or out.strip() == ""


def test_list_shows_added_entries(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "alpha")
    _seed(monkeypatch, "beta", tags=["dev"])
    capsys.readouterr()  # clear seed output
    cli.main(["list"])
    out = capsys.readouterr().out
    assert "alpha" in out
    assert "beta" in out


def test_list_filter_by_tag(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "x-with-tag", tags=["llm"])
    _seed(monkeypatch, "x-without-tag")
    capsys.readouterr()
    cli.main(["list", "--tag", "llm"])
    out = capsys.readouterr().out
    assert "x-with-tag" in out
    assert "x-without-tag" not in out


def test_list_search_by_name_substring(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "openrouter-cline")
    _seed(monkeypatch, "stripe-test")
    capsys.readouterr()
    cli.main(["list", "--search", "router"])
    out = capsys.readouterr().out
    assert "openrouter-cline" in out
    assert "stripe-test" not in out


def test_info_shows_metadata_no_value(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "info-target", note="my note")
    capsys.readouterr()
    cli.main(["info", "info-target"])
    out = capsys.readouterr().out
    assert "info-target" in out
    assert "my note" in out
    assert "v\n" not in out  # secret value never printed


def test_info_unknown_name_errors(cli_env, capsys):
    rc = cli.main(["info", "does-not-exist"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "not found" in err.lower() or "no entry" in err.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli_add.py tests/test_cli_read.py -v`
Expected: ImportError on `keys_keeper.cli`.

- [ ] **Step 3: Write `src/keys_keeper/cli.py` (initial version with add/list/info)**

```python
"""keys CLI — argparse routing + subcommand dispatch."""
from __future__ import annotations
import argparse
import os
import subprocess
import sys
from pathlib import Path

from keys_keeper import __version__
from keys_keeper.audit import AuditLog
from keys_keeper.backend import KeychainBackend, MacOSKeychainBackend
from keys_keeper.models import Entry, EntryType, ValidationError
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore, NameConflict, NotFound, StoreError


# ----- backend factory (test override hook) -----

def _backend() -> KeychainBackend:
    return MacOSKeychainBackend(
        service=os.environ.get("KEYS_KEEPER_TEST_SERVICE", "keys-keeper"),
        keychain_path=os.environ.get("KEYS_KEEPER_TEST_KEYCHAIN"),
    )


# ----- input source resolution -----

def _read_input(args: argparse.Namespace) -> str:
    sources = [
        bool(args.from_clipboard),
        bool(args.from_file),
        bool(args.stdin),
        bool(args.web),
    ]
    if sum(sources) != 1:
        sys.stderr.write(
            "error: must specify exactly one input source: "
            "--from-clipboard | --from-file PATH | --stdin | --web\n"
        )
        return ""
    if args.from_clipboard:
        result = subprocess.run(["pbpaste"], capture_output=True, text=True)
        return result.stdout
    if args.from_file:
        return Path(args.from_file).read_text()
    if args.stdin:
        return sys.stdin.read().rstrip("\n")
    if args.web:
        sys.stderr.write("--web flag is implemented in admin UI; not supported here yet\n")
        return ""
    return ""


# ----- subcommand handlers -----

def cmd_add(args: argparse.Namespace) -> int:
    paths = Paths()
    paths.ensure()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = _backend()

    value = _read_input(args)
    if not value and not args.from_file:
        return 2

    fields: dict = {}
    if args.service:
        fields["service"] = args.service
    type_ = EntryType(args.type)
    try:
        entry = Entry.new(
            name=args.name,
            type=type_,
            fields=fields,
            tags=args.tag or [],
            note=args.note or "",
        )
    except ValidationError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    try:
        if args.replace:
            existing = store.get_by_name(args.name)
            if existing:
                entry.id = existing.id  # reuse keychain account
                store.replace_by_name(entry)
            else:
                store.add(entry)
        else:
            store.add(entry)
    except NameConflict as e:
        sys.stderr.write(f"error: {e}\n")
        return 1

    backend.set(entry.id, value)
    audit.record(op="add", name=entry.name, id_=entry.id, success=True)
    print(f"added {entry.type.value} '{entry.name}' (id={entry.id})")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store = MetadataStore(Paths())
    entries = store.list()
    if args.type:
        entries = [e for e in entries if e.type.value == args.type]
    if args.tag:
        entries = [e for e in entries if args.tag in e.tags]
    if args.search:
        q = args.search.lower()
        entries = [e for e in entries if q in e.name.lower() or q in (e.note or "").lower()]
    if not entries:
        print("no entries")
        return 0
    for e in entries:
        tag_str = "[" + ",".join(e.tags) + "]" if e.tags else ""
        print(f"{e.type.value:10s}  {e.name:30s}  {tag_str}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    store = MetadataStore(Paths())
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    print(f"name:       {e.name}")
    print(f"type:       {e.type.value}")
    print(f"id:         {e.id}")
    print(f"created:    {e.created_at}")
    print(f"updated:    {e.updated_at}")
    print(f"tags:       {', '.join(e.tags) or '-'}")
    print(f"note:       {e.note or '-'}")
    if e.fields:
        print("fields:")
        for k, v in e.fields.items():
            print(f"  {k}: {v}")
    if e.refs:
        print("refs:")
        for r in e.refs:
            print(f"  {r['role']} -> {r['name']}")
    return 0


# ----- top-level parser -----

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="keys", description="personal secrets manager")
    p.add_argument("--version", action="version", version=f"keys-keeper {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # add
    a = sub.add_parser("add", help="add a new entry")
    a.add_argument("name")
    a.add_argument("--type", choices=[t.value for t in EntryType], default="api_key")
    a.add_argument("--from-clipboard", action="store_true")
    a.add_argument("--from-file")
    a.add_argument("--stdin", action="store_true")
    a.add_argument("--web", action="store_true")
    a.add_argument("--service")
    a.add_argument("--tag", action="append", default=[])
    a.add_argument("--note", default="")
    a.add_argument("--replace", action="store_true")
    a.set_defaults(func=cmd_add)

    # list
    l = sub.add_parser("list", help="list entries")
    l.add_argument("--type")
    l.add_argument("--tag")
    l.add_argument("--search")
    l.set_defaults(func=cmd_list)

    # info
    i = sub.add_parser("info", help="show entry metadata (no value)")
    i.add_argument("name")
    i.set_defaults(func=cmd_info)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_cli_add.py tests/test_cli_read.py -v`
Expected: all green.

- [ ] **Step 5: Manual smoke test**

```bash
keys add manual-smoke --type api_key --stdin --tag manual-test <<<"smoke-secret"
keys list
keys info manual-smoke
```

Expected: `add` prints success, `list` shows entry, `info` shows metadata but never the value.

- [ ] **Step 6: Commit**

```bash
git add src/keys_keeper/cli.py tests/test_cli_add.py tests/test_cli_read.py
git commit -m "feat: keys add/list/info with input-source flags"
```

### Task 1.7: CLI commands `reveal` (gated) + `copy` (with hash-and-clear)

**Files:**
- Modify: `src/keys_keeper/cli.py` (add subcommands)
- Create: `tests/test_cli_copy_inject.py` (covers `reveal` and `copy`)

- [ ] **Step 1: Write the failing test**

`tests/test_cli_copy_inject.py`:

```python
import os
import subprocess
import time
import pytest
from io import StringIO
from keys_keeper import cli


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def _add(name, value, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO(value + "\n"))
    cli.main(["add", name, "--type", "api_key", "--stdin"])


def test_reveal_blocked_without_env_var(cli_env, capsys, monkeypatch):
    monkeypatch.delenv("KEYS_KEEPER_ALLOW_REVEAL", raising=False)
    _add("rev1", "secret-val", monkeypatch)
    capsys.readouterr()
    rc = cli.main(["reveal", "rev1"])
    assert rc != 0
    err = capsys.readouterr().err.lower()
    assert "keys_keeper_allow_reveal" in err
    assert "secret-val" not in err


def test_reveal_with_env_prints_value(cli_env, capsys, monkeypatch):
    _add("rev2", "secret-val-2", monkeypatch)
    monkeypatch.setenv("KEYS_KEEPER_ALLOW_REVEAL", "1")
    capsys.readouterr()
    rc = cli.main(["reveal", "rev2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "secret-val-2" in out


def test_reveal_unknown_name(cli_env, capsys, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_ALLOW_REVEAL", "1")
    rc = cli.main(["reveal", "ghost"])
    assert rc != 0


def test_copy_writes_to_pbcopy(cli_env, capsys, monkeypatch):
    _add("cp1", "clip-secret", monkeypatch)
    capsys.readouterr()
    rc = cli.main(["copy", "cp1"])
    assert rc == 0
    pasted = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout
    assert pasted == "clip-secret"
    out = capsys.readouterr().out
    assert "clip-secret" not in out  # never echoed
    assert "copied" in out.lower()


def test_copy_records_audit(cli_env, monkeypatch):
    from keys_keeper.audit import AuditLog
    from keys_keeper.paths import Paths
    _add("cp2", "v2", monkeypatch)
    cli.main(["copy", "cp2"])
    events = list(AuditLog(Paths()).search(op="copy"))
    assert any(e["name"] == "cp2" for e in events)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli_copy_inject.py -v`
Expected: AttributeError or unknown subcommand on `reveal` and `copy`.

- [ ] **Step 3: Add `reveal` and `copy` to `cli.py`**

Append to `src/keys_keeper/cli.py` (above the `build_parser` function):

```python
import hashlib
import threading


def cmd_reveal(args: argparse.Namespace) -> int:
    if os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") != "1":
        sys.stderr.write(
            "error: `keys reveal` requires KEYS_KEEPER_ALLOW_REVEAL=1 in env. "
            "Add to ~/.zshrc to enable. (This guard exists so AI agents can't accidentally "
            "extract plaintext.)\n"
        )
        return 2
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    backend = _backend()
    try:
        value = backend.get(e.id)
    except Exception as ex:
        audit.record(op="reveal", name=e.name, id_=e.id, success=False, error=str(ex))
        sys.stderr.write(f"failed to read keychain: {ex}\n")
        return 1
    if args.as_env:
        # NAME=value format for `eval $(keys reveal X --as-env)`
        env_name = e.name.upper().replace("-", "_").replace(".", "_")
        print(f"{env_name}={_shell_quote(value)}")
    else:
        sys.stdout.write(value)
        if not value.endswith("\n"):
            sys.stdout.write("\n")
    audit.record(op="reveal", name=e.name, id_=e.id, success=True)
    return 0


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def cmd_copy(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    backend = _backend()
    try:
        value = backend.get(e.id)
    except Exception as ex:
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error=str(ex))
        sys.stderr.write(f"failed to read keychain: {ex}\n")
        return 1

    proc = subprocess.run(["pbcopy"], input=value, text=True)
    if proc.returncode != 0:
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error="pbcopy failed")
        sys.stderr.write("pbcopy failed\n")
        return 1

    written_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    print(f"copied {e.name} to clipboard · auto-clear in {args.clear_after}s")
    audit.record(op="copy", name=e.name, id_=e.id, success=True)

    if args.clear_after > 0:
        # Spawn a detached process to handle the clear, so this CLI exits immediately.
        clear_script = (
            f"sleep {args.clear_after}; "
            f"current=$(pbpaste 2>/dev/null); "
            f"current_hash=$(echo -n \"$current\" | shasum -a 256 | cut -d' ' -f1); "
            f"if [ \"$current_hash\" = \"{written_hash}\" ]; then printf '' | pbcopy; fi"
        )
        subprocess.Popen(
            ["sh", "-c", clear_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    return 0
```

Update `build_parser()`:

```python
    # reveal
    rv = sub.add_parser("reveal", help="print value to stdout (gated by env-var)")
    rv.add_argument("name")
    rv.add_argument("--as-env", action="store_true", help="print as NAME=value for eval")
    rv.set_defaults(func=cmd_reveal)

    # copy
    cp = sub.add_parser("copy", help="copy value to clipboard with auto-clear")
    cp.add_argument("name")
    cp.add_argument("--clear-after", type=int, default=30, help="seconds before auto-clear (0 = never)")
    cp.set_defaults(func=cmd_copy)
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_cli_copy_inject.py -v`
Expected: 5 passed.

- [ ] **Step 5: Manual smoke test**

```bash
keys add tmp-copy --type api_key --stdin <<<"copy-test"
keys copy tmp-copy
pbpaste                     # should print: copy-test
unset KEYS_KEEPER_ALLOW_REVEAL
keys reveal tmp-copy        # should error
KEYS_KEEPER_ALLOW_REVEAL=1 keys reveal tmp-copy   # should print value
```

- [ ] **Step 6: Commit**

```bash
git add src/keys_keeper/cli.py tests/test_cli_copy_inject.py
git commit -m "feat: keys reveal (env-gated) + copy (hash-and-clear)"
```

### Task 1.8: CLI commands `inject` + `resolve` + `rm` + `edit` + `doctor`

**Files:**
- Modify: `src/keys_keeper/cli.py`
- Create: `tests/test_cli_edit_rm.py`
- Create: `tests/test_cli_doctor.py`
- Modify: `tests/test_cli_copy_inject.py` (add inject + resolve tests)

- [ ] **Step 1: Append `inject` and `resolve` tests**

Append to `tests/test_cli_copy_inject.py`:

```python
def test_inject_appends_env_to_file(cli_env, tmp_path, monkeypatch):
    _add("inj1", "injected-value", monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING=foo\n")
    rc = cli.main(["inject", "inj1", "--file", str(env_file), "--as", "MY_KEY"])
    assert rc == 0
    content = env_file.read_text()
    assert "EXISTING=foo" in content
    assert "MY_KEY=injected-value" in content


def test_inject_refuses_existing_env_without_replace(cli_env, tmp_path, monkeypatch):
    _add("inj2", "v", monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("MY_KEY=old\n")
    rc = cli.main(["inject", "inj2", "--file", str(env_file), "--as", "MY_KEY"])
    assert rc != 0


def test_inject_replaces_existing_env_with_flag(cli_env, tmp_path, monkeypatch):
    _add("inj3", "new-val", monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("MY_KEY=old\nOTHER=keep\n")
    rc = cli.main(["inject", "inj3", "--file", str(env_file), "--as", "MY_KEY", "--replace"])
    assert rc == 0
    content = env_file.read_text()
    assert "MY_KEY=new-val" in content
    assert "OTHER=keep" in content
    assert "MY_KEY=old" not in content


def test_resolve_replaces_placeholders(cli_env, tmp_path, monkeypatch):
    _add("rs1", "resolved-val", monkeypatch)
    target = tmp_path / "config"
    target.write_text("API=__KEYS:rs1__\nLITERAL=keep\n")
    rc = cli.main(["resolve", str(target)])
    assert rc == 0
    content = target.read_text()
    assert "API=resolved-val" in content
    assert "LITERAL=keep" in content
    assert "__KEYS:" not in content


def test_resolve_unknown_name_fails(cli_env, tmp_path):
    target = tmp_path / "x"
    target.write_text("X=__KEYS:does-not-exist__\n")
    rc = cli.main(["resolve", str(target)])
    assert rc != 0
```

- [ ] **Step 2: Write `tests/test_cli_edit_rm.py`**

```python
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def _add(name, monkeypatch, **kw):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    args = ["add", name, "--type", "api_key", "--stdin"]
    for t in kw.get("tags", []):
        args += ["--tag", t]
    if "note" in kw:
        args += ["--note", kw["note"]]
    cli.main(args)


def test_edit_add_tag(cli_env, monkeypatch):
    _add("ed1", monkeypatch, tags=["a"])
    cli.main(["edit", "ed1", "--add-tag", "b"])
    e = MetadataStore(Paths()).get_by_name("ed1")
    assert set(e.tags) == {"a", "b"}


def test_edit_remove_tag(cli_env, monkeypatch):
    _add("ed2", monkeypatch, tags=["a", "b"])
    cli.main(["edit", "ed2", "--rm-tag", "a"])
    e = MetadataStore(Paths()).get_by_name("ed2")
    assert e.tags == ["b"]


def test_edit_change_note(cli_env, monkeypatch):
    _add("ed3", monkeypatch, note="old")
    cli.main(["edit", "ed3", "--note", "new note"])
    e = MetadataStore(Paths()).get_by_name("ed3")
    assert e.note == "new note"


def test_edit_rename(cli_env, monkeypatch):
    _add("ed4", monkeypatch)
    cli.main(["edit", "ed4", "--name", "ed4-renamed"])
    assert MetadataStore(Paths()).get_by_name("ed4") is None
    assert MetadataStore(Paths()).get_by_name("ed4-renamed") is not None


def test_rm_deletes_entry(cli_env, monkeypatch, capsys):
    _add("to-delete", monkeypatch)
    rc = cli.main(["rm", "to-delete"])
    assert rc == 0
    assert MetadataStore(Paths()).get_by_name("to-delete") is None


def test_rm_missing_returns_error(cli_env):
    rc = cli.main(["rm", "ghost"])
    assert rc != 0
```

- [ ] **Step 3: Write `tests/test_cli_doctor.py`**

```python
import pytest
from keys_keeper import cli


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def test_doctor_creates_paths_and_returns_0(cli_env, capsys):
    rc = cli.main(["doctor"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "data.json" in out
    assert "audit.jsonl" in out


def test_doctor_warns_when_reveal_env_missing(cli_env, capsys, monkeypatch):
    monkeypatch.delenv("KEYS_KEEPER_ALLOW_REVEAL", raising=False)
    cli.main(["doctor"])
    out = capsys.readouterr().out
    assert "KEYS_KEEPER_ALLOW_REVEAL" in out
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `pytest tests/test_cli_copy_inject.py tests/test_cli_edit_rm.py tests/test_cli_doctor.py -v`
Expected: unknown-subcommand failures.

- [ ] **Step 5: Append handlers to `src/keys_keeper/cli.py`**

```python
import re

# inject
def cmd_inject(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    backend = _backend()
    value = backend.get(e.id)
    target = Path(args.file)
    if target.exists():
        existing = target.read_text()
        existing_lines = existing.splitlines()
        match_idx = None
        for i, line in enumerate(existing_lines):
            if line.startswith(f"{args.as_env}="):
                match_idx = i
                break
        if match_idx is not None:
            if not args.replace:
                sys.stderr.write(
                    f"error: {args.as_env} already exists in {target} "
                    f"(use --replace to overwrite)\n"
                )
                return 1
            existing_lines[match_idx] = f"{args.as_env}={value}"
            new_content = "\n".join(existing_lines) + ("\n" if existing.endswith("\n") else "")
        else:
            sep = "" if existing.endswith("\n") or not existing else "\n"
            new_content = existing + sep + f"{args.as_env}={value}\n"
    else:
        new_content = f"{args.as_env}={value}\n"
    target.write_text(new_content)
    audit.record(op="inject", name=e.name, id_=e.id, file_target=str(target), success=True)
    print(f"injected {e.name} → {target} as {args.as_env}")
    return 0


# resolve
_RESOLVE_RE = re.compile(r"__KEYS:([a-z0-9][a-z0-9._-]*[a-z0-9])(?::([a-z_]+))?__")


def cmd_resolve(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = _backend()
    target = Path(args.file)
    content = target.read_text()
    errors = []
    count = 0

    def replace(match: re.Match) -> str:
        nonlocal count
        name = match.group(1)
        field_name = match.group(2)
        e = store.get_by_name(name)
        if e is None:
            errors.append(f"unknown entry: {name}")
            return match.group(0)
        if field_name:
            v = e.fields.get(field_name)
            if v is None:
                errors.append(f"entry {name} has no field {field_name}")
                return match.group(0)
            count += 1
            return str(v)
        else:
            count += 1
            try:
                return backend.get(e.id)
            except Exception as ex:
                errors.append(f"keychain miss for {name}: {ex}")
                return match.group(0)

    new_content = _RESOLVE_RE.sub(replace, content)
    if errors:
        sys.stderr.write("error: resolve failed:\n")
        for err in errors:
            sys.stderr.write(f"  - {err}\n")
        return 1
    target.write_text(new_content)
    audit.record(op="resolve", name="<file>", id_=str(target), file_target=str(target), success=True)
    print(f"resolved {count} placeholder(s) in {target}")
    return 0


# rm
def cmd_rm(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    # check reverse refs
    dependents = [
        x for x in store.list()
        if any(r.get("name") == e.name for r in x.refs)
    ]
    if dependents and not args.cascade:
        sys.stderr.write(
            f"error: {e.name} is referenced by: {[d.name for d in dependents]}. "
            f"Use --cascade to remove the references too.\n"
        )
        return 1
    if dependents and args.cascade:
        for d in dependents:
            d.refs = [r for r in d.refs if r.get("name") != e.name]
            store.update(d)
    store.delete_by_name(args.name)
    backend = _backend()
    backend.delete(e.id)
    backend.delete(e.id + ":passphrase")  # in case ssh_key had passphrase
    audit.record(op="delete", name=e.name, id_=e.id, success=True)
    print(f"removed {e.name}")
    return 0


# edit
def cmd_edit(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    if args.add_tag:
        for t in args.add_tag:
            if t not in e.tags:
                e.tags.append(t)
    if args.rm_tag:
        e.tags = [t for t in e.tags if t not in args.rm_tag]
    if args.note is not None:
        e.note = args.note
    if args.field:
        for kv in args.field:
            k, _, v = kv.partition("=")
            if not _:
                sys.stderr.write(f"--field expects KEY=VALUE, got {kv!r}\n")
                return 2
            e.fields[k] = v
    if args.ref:
        for kv in args.ref:
            role, _, name = kv.partition("=")
            if not _:
                sys.stderr.write(f"--ref expects ROLE=NAME, got {kv!r}\n")
                return 2
            e.refs = [r for r in e.refs if r.get("role") != role]
            e.refs.append({"role": role, "name": name})
    if args.new_name:
        try:
            from keys_keeper.models import validate_name
            validate_name(args.new_name)
        except Exception as ex:
            sys.stderr.write(f"error: {ex}\n")
            return 2
        if store.get_by_name(args.new_name) is not None:
            sys.stderr.write(f"error: name {args.new_name!r} already taken\n")
            return 1
        e.name = args.new_name
    e.updated_at = __import__("keys_keeper.models", fromlist=["_now_iso"])._now_iso()
    store.update(e)
    audit.record(op="update", name=e.name, id_=e.id, success=True)
    print(f"updated {e.name}")
    return 0


# doctor
def cmd_doctor(args: argparse.Namespace) -> int:
    paths = Paths()
    paths.ensure()
    print(f"keys-keeper {__version__}")
    print(f"config dir: {paths.root}")
    print(f"  data.json:    {'exists' if paths.data_json.exists() else 'will be created on first add'}")
    print(f"  audit.jsonl:  {'exists' if paths.audit_jsonl.exists() else '(none yet)'}")
    print(f"  config.toml:  {'exists' if paths.config_toml.exists() else '(default)'}")
    # keychain access probe
    try:
        backend = _backend()
        backend.list_ids()
        print("keychain:     ✓ accessible")
    except Exception as ex:
        print(f"keychain:     ✗ ERROR — {ex}")
    if os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") == "1":
        print("KEYS_KEEPER_ALLOW_REVEAL: ✓ set")
    else:
        print("KEYS_KEEPER_ALLOW_REVEAL: ⚠ not set — `keys reveal` will refuse to print plaintext")
        print("  add `export KEYS_KEEPER_ALLOW_REVEAL=1` to ~/.zshrc to enable")
    return 0
```

Append the new subparsers to `build_parser()`:

```python
    # inject
    inj = sub.add_parser("inject", help="append ENV=value to a file")
    inj.add_argument("name")
    inj.add_argument("--file", required=True)
    inj.add_argument("--as", dest="as_env", required=True, metavar="ENV_NAME")
    inj.add_argument("--replace", action="store_true")
    inj.set_defaults(func=cmd_inject)

    # resolve
    rs = sub.add_parser("resolve", help="replace __KEYS:name__ placeholders in a file")
    rs.add_argument("file")
    rs.set_defaults(func=cmd_resolve)

    # rm
    rm = sub.add_parser("rm", help="delete an entry")
    rm.add_argument("name")
    rm.add_argument("--cascade", action="store_true")
    rm.set_defaults(func=cmd_rm)

    # edit
    ed = sub.add_parser("edit", help="modify entry metadata")
    ed.add_argument("name")
    ed.add_argument("--name", dest="new_name")
    ed.add_argument("--add-tag", action="append", default=[])
    ed.add_argument("--rm-tag", action="append", default=[])
    ed.add_argument("--note", default=None)
    ed.add_argument("--field", action="append", default=[], help="KEY=VALUE")
    ed.add_argument("--ref", action="append", default=[], help="ROLE=NAME")
    ed.set_defaults(func=cmd_edit)

    # doctor
    dr = sub.add_parser("doctor", help="health check + paths")
    dr.set_defaults(func=cmd_doctor)
```

- [ ] **Step 6: Run tests to confirm they pass**

Run: `pytest tests/ -v --ignore=tests/test_e2e_admin.py`
Expected: all green.

- [ ] **Step 7: Manual smoke test**

```bash
keys add tmp-inject --type api_key --stdin <<<"inj-secret"
echo "OTHER=foo" > /tmp/test-env
keys inject tmp-inject --file /tmp/test-env --as MY_KEY
cat /tmp/test-env   # OTHER=foo + MY_KEY=inj-secret
keys edit tmp-inject --add-tag testing --note "smoke note"
keys info tmp-inject
keys rm tmp-inject
keys doctor
```

- [ ] **Step 8: Commit**

```bash
git add src/keys_keeper/cli.py tests/test_cli_*.py
git commit -m "feat: keys inject/resolve/rm/edit/doctor"
```

---

## Phase 2 — SSH + refs validation

### Task 2.1: refs module — cycle detection + reverse-ref index

**Files:**
- Create: `src/keys_keeper/refs.py`
- Create: `tests/test_refs.py`

- [ ] **Step 1: Write the failing test**

`tests/test_refs.py`:

```python
import pytest
from keys_keeper.models import Entry, EntryType
from keys_keeper.refs import (
    detect_cycles,
    reverse_refs,
    resolve_chain,
    RefCycleError,
    RefMissingError,
)


def _e(name, refs=None, type_=EntryType.SERVER, fields=None):
    return Entry.new(
        name=name,
        type=type_,
        fields=fields or {"host": "x", "user": "y", "auth": "ssh_key"} if type_ == EntryType.SERVER else (
            {"public_key": "ssh-..."} if type_ == EntryType.SSH_KEY else {}
        ),
        refs=refs or [],
    )


def test_detect_cycles_returns_none_for_dag():
    a = _e("a", refs=[{"role": "ssh_key", "name": "b"}])
    b = _e("b", type_=EntryType.SSH_KEY)
    detect_cycles([a, b])  # no error


def test_detect_cycles_raises_on_self_ref():
    a = _e("a", refs=[{"role": "ssh_key", "name": "a"}])
    with pytest.raises(RefCycleError):
        detect_cycles([a])


def test_detect_cycles_raises_on_two_node_cycle():
    a = _e("a", refs=[{"role": "ssh_key", "name": "b"}])
    b = _e("b", refs=[{"role": "ssh_key", "name": "a"}])
    with pytest.raises(RefCycleError):
        detect_cycles([a, b])


def test_reverse_refs_lists_dependents():
    a = _e("a", refs=[{"role": "ssh_key", "name": "shared-key"}])
    b = _e("b", refs=[{"role": "ssh_key", "name": "shared-key"}])
    shared = _e("shared-key", type_=EntryType.SSH_KEY)
    rev = reverse_refs([a, b, shared])
    assert set(rev["shared-key"]) == {"a", "b"}


def test_resolve_chain_finds_target():
    a = _e("server-a", refs=[{"role": "ssh_key", "name": "k1"}])
    k1 = _e("k1", type_=EntryType.SSH_KEY)
    target = resolve_chain([a, k1], "server-a", "ssh_key")
    assert target.name == "k1"


def test_resolve_chain_missing_raises():
    a = _e("server-a", refs=[{"role": "ssh_key", "name": "missing"}])
    with pytest.raises(RefMissingError):
        resolve_chain([a], "server-a", "ssh_key")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_refs.py -v`
Expected: ImportError on `keys_keeper.refs`.

- [ ] **Step 3: Write `src/keys_keeper/refs.py`**

```python
"""Ref resolution + cycle detection for entry → entry links."""
from __future__ import annotations
from collections import defaultdict
from keys_keeper.models import Entry


class RefError(RuntimeError):
    pass


class RefCycleError(RefError):
    pass


class RefMissingError(RefError):
    pass


def detect_cycles(entries: list[Entry]) -> None:
    """DFS-based cycle detection over the ref graph. Raises RefCycleError on any cycle."""
    by_name = {e.name: e for e in entries}
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {e.name: WHITE for e in entries}

    def dfs(name: str, path: list[str]) -> None:
        if name not in by_name:
            return
        color[name] = GRAY
        for ref in by_name[name].refs:
            target = ref.get("name")
            if target == name:
                raise RefCycleError(f"self-ref on {name}")
            if target in color and color[target] == GRAY:
                raise RefCycleError(f"cycle: {' -> '.join(path + [name, target])}")
            if target in color and color[target] == WHITE:
                dfs(target, path + [name])
        color[name] = BLACK

    for e in entries:
        if color[e.name] == WHITE:
            dfs(e.name, [])


def reverse_refs(entries: list[Entry]) -> dict[str, list[str]]:
    """Build {target_name: [dependent_name, ...]} from the ref graph."""
    rev: dict[str, list[str]] = defaultdict(list)
    for e in entries:
        for ref in e.refs:
            target = ref.get("name")
            if target:
                rev[target].append(e.name)
    return dict(rev)


def resolve_chain(entries: list[Entry], from_name: str, role: str) -> Entry:
    """Given entry name + ref role, return the linked target Entry."""
    by_name = {e.name: e for e in entries}
    src = by_name.get(from_name)
    if src is None:
        raise RefMissingError(f"no source entry {from_name!r}")
    for ref in src.refs:
        if ref.get("role") == role:
            target = by_name.get(ref.get("name"))
            if target is None:
                raise RefMissingError(
                    f"{from_name} → {role} → {ref.get('name')!r} (target missing)"
                )
            return target
    raise RefMissingError(f"{from_name} has no ref with role {role!r}")
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_refs.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/refs.py tests/test_refs.py
git commit -m "feat: refs module — cycle detection + resolution"
```

### Task 2.2: `keys ssh` — server entry resolution + tempfile-based key handoff

**Files:**
- Create: `src/keys_keeper/ssh_runner.py`
- Modify: `src/keys_keeper/cli.py`
- Create: `tests/test_cli_ssh.py`

- [ ] **Step 1: Write the failing test**

`tests/test_cli_ssh.py`:

```python
import os
from io import StringIO
from unittest.mock import patch
import pytest
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def _seed_server_with_key(monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("dummy-private-key-content\n"))
    cli.main([
        "add", "test-key", "--type", "ssh_key", "--stdin",
        "--field", "public_key=ssh-ed25519 AAA...",
    ])
    cli.main([
        "add", "test-server", "--type", "server",
        "--from-file", "/dev/null",  # server has no own secret, but CLI still requires source
        "--field", "host=1.2.3.4",
        "--field", "user=root",
        "--field", "port=22",
        "--field", "auth=ssh_key",
        "--ref", "ssh_key=test-key",
    ])


def test_ssh_invokes_ssh_with_resolved_key(cli_env, monkeypatch, tmp_path):
    _seed_server_with_key(monkeypatch)
    captured = {}
    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class R: returncode = 0
        return R()
    monkeypatch.setattr("subprocess.run", fake_run)
    rc = cli.main(["ssh", "test-server"])
    assert rc == 0
    assert captured["cmd"][0] == "ssh"
    assert "root@1.2.3.4" in captured["cmd"]
    # the -i flag must be followed by a path that exists at call time
    assert "-i" in captured["cmd"]


def test_ssh_unknown_server(cli_env):
    rc = cli.main(["ssh", "no-such-server"])
    assert rc != 0
```

> Note on the test: the design lets `--field` be used during `add` for non-required fields. We will widen `cmd_add` slightly to accept `--field K=V` pairs (used here to seed `public_key` for an `ssh_key` and the various server fields). This is cleaner than a separate seeding API.

- [ ] **Step 2: Add `--field` support to `cmd_add` and update its parser**

In `src/keys_keeper/cli.py`, modify `cmd_add` to merge `args.field` into `fields` dict (parsing `K=V` strings) and accept absent secret value for entries that don't need one (e.g. `server`, `domain`, `note` without `secret_body`).

```python
def cmd_add(args: argparse.Namespace) -> int:
    paths = Paths()
    paths.ensure()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = _backend()
    type_ = EntryType(args.type)

    # merge --field flags into fields dict
    fields: dict = {}
    if args.service:
        fields["service"] = args.service
    for kv in args.field or []:
        k, _, v = kv.partition("=")
        if not _:
            sys.stderr.write(f"--field expects KEY=VALUE, got {kv!r}\n")
            return 2
        # numeric coercion for known int fields
        if k == "port":
            v = int(v)
        elif k == "secret_body":
            v = v.lower() in ("1", "true", "yes")
        fields[k] = v

    # parse --ref flags
    refs = []
    for kv in args.ref or []:
        role, _, name = kv.partition("=")
        if not _:
            sys.stderr.write(f"--ref expects ROLE=NAME, got {kv!r}\n")
            return 2
        refs.append({"role": role, "name": name})

    # determine if this entry type stores a secret
    needs_secret = type_ in (EntryType.API_KEY, EntryType.SSH_KEY) or (
        type_ == EntryType.NOTE and fields.get("secret_body", False)
    )

    value = ""
    if needs_secret:
        value = _read_input(args)
        if not value and not args.from_file:
            return 2

    try:
        entry = Entry.new(
            name=args.name, type=type_, fields=fields,
            tags=args.tag or [], note=args.note or "", refs=refs,
        )
    except ValidationError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    try:
        if args.replace and store.get_by_name(args.name):
            existing = store.get_by_name(args.name)
            entry.id = existing.id
            store.replace_by_name(entry)
        else:
            store.add(entry)
    except NameConflict as e:
        sys.stderr.write(f"error: {e}\n")
        return 1

    if needs_secret:
        backend.set(entry.id, value)
    audit.record(op="add", name=entry.name, id_=entry.id, success=True)
    print(f"added {entry.type.value} '{entry.name}' (id={entry.id})")
    return 0
```

In `build_parser()` for the `add` subparser, also add:

```python
    a.add_argument("--field", action="append", default=[], help="KEY=VALUE")
    a.add_argument("--ref", action="append", default=[], help="ROLE=NAME")
```

Also relax the requirement in `_read_input` so that no source flag is OK when `needs_secret` is False — handle this by skipping `_read_input` for non-secret types (already done above).

- [ ] **Step 3: Write `src/keys_keeper/ssh_runner.py`**

```python
"""keys ssh — resolve server + ssh_key, write tempfile, exec ssh."""
from __future__ import annotations
import os
import subprocess
import tempfile
from keys_keeper.backend import KeychainBackend
from keys_keeper.models import Entry, EntryType
from keys_keeper.refs import resolve_chain, RefMissingError
from keys_keeper.store import MetadataStore


def run_ssh(
    *,
    store: MetadataStore,
    backend: KeychainBackend,
    server_name: str,
    extra_cmd: str | None = None,
) -> int:
    server = store.get_by_name(server_name)
    if server is None or server.type != EntryType.SERVER:
        raise ValueError(f"{server_name!r} is not a server entry")
    host = server.fields["host"]
    user = server.fields.get("user", "root")
    port = int(server.fields.get("port", 22))
    auth = server.fields.get("auth", "ssh_key")

    if auth == "ssh_key":
        try:
            ssh_entry = resolve_chain(store.list(), server_name, "ssh_key")
        except RefMissingError as e:
            raise ValueError(f"server {server_name} requires ssh_key ref: {e}")
        private_key = backend.get(ssh_entry.id)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False, dir=os.path.expanduser("~/.ssh") if os.path.exists(os.path.expanduser("~/.ssh")) else None,
        ) as tmp:
            os.chmod(tmp.name, 0o600)
            tmp.write(private_key)
            if not private_key.endswith("\n"):
                tmp.write("\n")
            tmp_path = tmp.name
        try:
            cmd = ["ssh", "-i", tmp_path, "-p", str(port), f"{user}@{host}"]
            if extra_cmd:
                cmd.append(extra_cmd)
            result = subprocess.run(cmd)
            return result.returncode
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
    elif auth == "password":
        cmd = ["ssh", "-p", str(port), f"{user}@{host}"]
        if extra_cmd:
            cmd.append(extra_cmd)
        return subprocess.run(cmd).returncode
    else:
        cmd = ["ssh", "-p", str(port), f"{user}@{host}"]
        if extra_cmd:
            cmd.append(extra_cmd)
        return subprocess.run(cmd).returncode
```

- [ ] **Step 4: Wire `cmd_ssh` into CLI**

Append to `src/keys_keeper/cli.py`:

```python
def cmd_ssh(args: argparse.Namespace) -> int:
    from keys_keeper.ssh_runner import run_ssh
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = _backend()
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    try:
        rc = run_ssh(store=store, backend=backend, server_name=args.name, extra_cmd=args.cmd)
    except ValueError as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    audit.record(op="ssh", name=e.name, id_=e.id, success=(rc == 0))
    return rc
```

In `build_parser()`:

```python
    sh = sub.add_parser("ssh", help="open ssh session to a server entry")
    sh.add_argument("name")
    sh.add_argument("--cmd", help="run a one-shot command instead of interactive shell")
    sh.set_defaults(func=cmd_ssh)
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `pytest tests/ -v --ignore=tests/test_e2e_admin.py`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/keys_keeper/ssh_runner.py src/keys_keeper/cli.py tests/test_cli_ssh.py
git commit -m "feat: keys ssh with resolved key + tempfile cleanup"
```

### Task 2.3: `keys list/info` show refs + reverse refs

**Files:**
- Modify: `src/keys_keeper/cli.py`

- [ ] **Step 1: Add reverse-ref display to `cmd_info`**

In `cmd_info`, after the existing `refs` block, add:

```python
    # reverse refs
    from keys_keeper.refs import reverse_refs
    rev = reverse_refs(store.list())
    if e.name in rev:
        print("used by:")
        for dependent in rev[e.name]:
            print(f"  {dependent}")
```

- [ ] **Step 2: Add a quick test**

Append to `tests/test_cli_read.py`:

```python
def test_info_shows_reverse_refs(cli_env, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("k\n"))
    cli.main([
        "add", "ref-target", "--type", "ssh_key", "--stdin",
        "--field", "public_key=ssh-...",
    ])
    cli.main([
        "add", "ref-server", "--type", "server",
        "--from-file", "/dev/null",
        "--field", "host=h", "--field", "user=u", "--field", "auth=ssh_key",
        "--ref", "ssh_key=ref-target",
    ])
    capsys.readouterr()
    cli.main(["info", "ref-target"])
    out = capsys.readouterr().out
    assert "used by" in out.lower()
    assert "ref-server" in out
```

- [ ] **Step 3: Run tests + commit**

```bash
pytest tests/test_cli_read.py -v
git add src/keys_keeper/cli.py tests/test_cli_read.py
git commit -m "feat: keys info shows reverse refs"
```

---

## Phase 3 — Web admin scaffold

### Task 3.1: HTTP server skeleton + token auth + auto-shutdown

**Files:**
- Create: `src/keys_keeper/server.py`
- Create: `tests/test_server_auth.py`

- [ ] **Step 1: Write the failing test**

`tests/test_server_auth.py`:

```python
import threading
import time
import urllib.request
import urllib.error
import pytest
from keys_keeper.paths import Paths
from keys_keeper.server import AdminServer


@pytest.fixture
def admin(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    paths = Paths()
    paths.ensure()
    server = AdminServer(paths=paths, port=0, idle_timeout_sec=60)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # wait for bind
    while server.bound_port == 0:
        time.sleep(0.01)
    yield server
    server.stop()


def _fetch(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Sec-Keys-Token", token)
    return urllib.request.urlopen(req, timeout=2)


def test_request_without_token_returns_403(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/api/entries"
    with pytest.raises(urllib.error.HTTPError) as ex:
        _fetch(url)
    assert ex.value.code == 403


def test_request_with_correct_token_succeeds(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/api/entries"
    resp = _fetch(url, token=admin.token)
    assert resp.status == 200


def test_request_with_wrong_token_returns_403(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/api/entries"
    with pytest.raises(urllib.error.HTTPError) as ex:
        _fetch(url, token="wrong-token")
    assert ex.value.code == 403


def test_initial_html_response_includes_token_in_query(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/?t={admin.token}"
    resp = _fetch(url)
    assert resp.status == 200
    body = resp.read().decode("utf-8")
    assert admin.token in body
    # the JS should contain history.replaceState to strip the token
    assert "history.replaceState" in body or "replaceState" in body


def test_no_cache_headers_on_responses(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/?t={admin.token}"
    resp = _fetch(url)
    assert "no-store" in resp.headers.get("Cache-Control", "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_server_auth.py -v`
Expected: ImportError on `keys_keeper.server`.

- [ ] **Step 3: Write `src/keys_keeper/server.py` (skeleton)**

```python
"""Localhost admin HTTP server with token auth."""
from __future__ import annotations
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from keys_keeper.paths import Paths


_NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'",
}


class AdminServer:
    """Wraps ThreadingHTTPServer with idle-timeout auto-shutdown and a generated session token."""

    def __init__(self, *, paths: Paths, port: int = 7777, idle_timeout_sec: int = 900):
        self.paths = paths
        self.requested_port = port
        self.bound_port = 0
        self.idle_timeout_sec = idle_timeout_sec
        self.token = secrets.token_hex(32)
        self.last_seen = time.monotonic()
        self._server: ThreadingHTTPServer | None = None
        self._stop_event = threading.Event()

    # ---- public ----

    def serve_forever(self) -> None:
        handler_cls = make_handler(self)
        self._server = ThreadingHTTPServer(("127.0.0.1", self.requested_port), handler_cls)
        self.bound_port = self._server.server_port
        threading.Thread(target=self._idle_watchdog, daemon=True).start()
        self._server.serve_forever()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server is not None:
            self._server.shutdown()

    def heartbeat(self) -> None:
        self.last_seen = time.monotonic()

    # ---- internal ----

    def _idle_watchdog(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(5)
            if time.monotonic() - self.last_seen > self.idle_timeout_sec:
                self.stop()
                return


def make_handler(admin: "AdminServer"):
    paths = admin.paths

    class Handler(BaseHTTPRequestHandler):
        # silence default noisy logging during tests
        def log_message(self, fmt: str, *args) -> None:
            return

        # ---- helpers ----

        def _verify_token(self) -> bool:
            # Accept token via header (preferred) or via query string on initial HTML load.
            header_token = self.headers.get("Sec-Keys-Token")
            if header_token == admin.token:
                return True
            # Allow query-string token only on GET HTML pages
            qs = parse_qs(urlparse(self.path).query)
            if qs.get("t", [""])[0] == admin.token:
                return True
            return False

        def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _NO_CACHE_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, payload: dict | list) -> None:
            data = json.dumps(payload).encode("utf-8")
            self._send(status, data, "application/json")

        # ---- routing ----

        def do_GET(self) -> None:
            admin.heartbeat()
            parsed = urlparse(self.path)
            path = parsed.path
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            if path == "/" or path == "/index.html":
                from keys_keeper.pages import render_dashboard
                html = render_dashboard(paths=paths, token=admin.token)
                self._send(200, html.encode("utf-8"))
                return
            if path.startswith("/api/"):
                from keys_keeper.api import handle_api
                handle_api(self, paths=paths, method="GET", path=path, body=None)
                return
            if path.startswith("/static/"):
                self._serve_static(path)
                return
            self._send(404, b"not found")

        def do_POST(self) -> None:
            admin.heartbeat()
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            from keys_keeper.api import handle_api
            handle_api(self, paths=paths, method="POST", path=urlparse(self.path).path, body=body)

        def _serve_static(self, path: str) -> None:
            asset = (Path(__file__).parent / path.lstrip("/")).resolve()
            base = (Path(__file__).parent / "static").resolve()
            if not str(asset).startswith(str(base)) or not asset.is_file():
                self._send(404, b"not found")
                return
            content_type = (
                "text/css" if asset.suffix == ".css"
                else "application/javascript" if asset.suffix == ".js"
                else "application/octet-stream"
            )
            self._send(200, asset.read_bytes(), content_type)

    return Handler
```

Stub `pages.py` and `api.py` so imports don't fail:

`src/keys_keeper/pages.py`:

```python
"""Server-rendered HTML pages."""
from pathlib import Path
from keys_keeper.paths import Paths


def render_dashboard(*, paths: Paths, token: str) -> str:
    # Minimal HTML that includes the token in the URL initially and strips it via JS.
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>keys-keeper · admin</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<noscript>JavaScript required.</noscript>
<div id="app">Loading dashboard…</div>
<script>
const TOKEN = "{token}";
sessionStorage.setItem("kk_token", TOKEN);
history.replaceState({{}}, "", "/");
</script>
<script src="/static/app.js"></script>
</body>
</html>
"""
```

`src/keys_keeper/api.py`:

```python
"""JSON API handlers."""
from __future__ import annotations
import json
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


def handle_api(handler, *, paths: Paths, method: str, path: str, body: bytes | None) -> None:
    if path == "/api/entries" and method == "GET":
        store = MetadataStore(paths)
        items = [e.to_dict() for e in store.list()]
        handler._send_json(200, {"entries": items})
        return
    if path == "/api/heartbeat" and method == "POST":
        # The server already heartbeats on every request; this endpoint is just a
        # cheap ping the page calls every 60s.
        handler._send_json(200, {"ok": True})
        return
    handler._send_json(404, {"error": "not found"})
```

Also create empty static dir and bare files so static serving works:

`src/keys_keeper/static/app.css`:

```css
body { font-family: -apple-system, sans-serif; background: #0a0b0c; color: #e8e9eb; margin: 0; padding: 24px; }
```

`src/keys_keeper/static/app.js`:

```javascript
// placeholder — real dashboard JS lands in Task 3.4
console.log("keys-keeper admin loaded");
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_server_auth.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/server.py src/keys_keeper/pages.py src/keys_keeper/api.py src/keys_keeper/static/ tests/test_server_auth.py
git commit -m "feat: admin HTTP server scaffold with token auth + idle shutdown"
```

### Task 3.2: JSON API — `/api/entries`, `/api/copy`, `/api/heartbeat`, `/api/shutdown`

**Files:**
- Modify: `src/keys_keeper/api.py`
- Create: `tests/test_server_api.py`

- [ ] **Step 1: Write the failing test**

`tests/test_server_api.py`:

```python
import json
import threading
import time
import urllib.request
import urllib.error
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.server import AdminServer


@pytest.fixture
def admin(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    paths = Paths()
    paths.ensure()
    server = AdminServer(paths=paths, port=0, idle_timeout_sec=60)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    while server.bound_port == 0:
        time.sleep(0.01)
    yield server
    server.stop()


def _post(admin, path, payload=None):
    data = json.dumps(payload).encode() if payload else b""
    req = urllib.request.Request(
        f"http://127.0.0.1:{admin.bound_port}{path}",
        data=data,
        method="POST",
    )
    req.add_header("Sec-Keys-Token", admin.token)
    req.add_header("Content-Type", "application/json")
    return urllib.request.urlopen(req, timeout=2)


def _get(admin, path):
    req = urllib.request.Request(f"http://127.0.0.1:{admin.bound_port}{path}")
    req.add_header("Sec-Keys-Token", admin.token)
    return urllib.request.urlopen(req, timeout=2)


def _seed(monkeypatch, name, value="v"):
    monkeypatch.setattr("sys.stdin", StringIO(value + "\n"))
    cli.main(["add", name, "--type", "api_key", "--stdin"])


def test_api_entries_returns_seeded_data(admin, monkeypatch):
    _seed(monkeypatch, "api-test-1")
    _seed(monkeypatch, "api-test-2")
    resp = _get(admin, "/api/entries")
    data = json.loads(resp.read())
    names = {e["name"] for e in data["entries"]}
    assert "api-test-1" in names
    assert "api-test-2" in names
    # values must NEVER appear in response
    body_str = json.dumps(data)
    assert "v\n" not in body_str
    assert "value" not in body_str.lower() or "value" not in [k for e in data["entries"] for k in e.get("fields", {})]


def test_api_copy_writes_clipboard_and_audits(admin, monkeypatch):
    _seed(monkeypatch, "copy-target", value="copy-secret-v")
    entries = json.loads(_get(admin, "/api/entries").read())["entries"]
    entry_id = next(e["id"] for e in entries if e["name"] == "copy-target")
    resp = _post(admin, "/api/copy", {"id": entry_id})
    payload = json.loads(resp.read())
    assert payload["ok"] is True
    import subprocess
    pasted = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout
    assert pasted == "copy-secret-v"
    # audit
    from keys_keeper.audit import AuditLog
    events = list(AuditLog(Paths()).search(op="copy"))
    assert any(e["name"] == "copy-target" for e in events)


def test_api_heartbeat_returns_ok(admin):
    resp = _post(admin, "/api/heartbeat")
    assert json.loads(resp.read())["ok"] is True


def test_api_shutdown_stops_server(admin):
    _post(admin, "/api/shutdown")
    time.sleep(0.2)
    with pytest.raises(Exception):
        _get(admin, "/api/entries")


def test_api_audit_returns_recent_events(admin, monkeypatch):
    _seed(monkeypatch, "audit-target")
    resp = _get(admin, "/api/audit?limit=10")
    events = json.loads(resp.read())["events"]
    assert any(e["name"] == "audit-target" for e in events)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_server_api.py -v`
Expected: 404s on `/api/copy`, `/api/shutdown`, `/api/audit`.

- [ ] **Step 3: Implement remaining API in `src/keys_keeper/api.py`**

Replace `src/keys_keeper/api.py` with:

```python
"""JSON API handlers for the admin server."""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlparse
from keys_keeper.audit import AuditLog
from keys_keeper.backend import MacOSKeychainBackend
from keys_keeper.paths import Paths
from keys_keeper.refs import reverse_refs
from keys_keeper.store import MetadataStore


def _backend():
    return MacOSKeychainBackend(
        service=os.environ.get("KEYS_KEEPER_TEST_SERVICE", "keys-keeper"),
        keychain_path=os.environ.get("KEYS_KEEPER_TEST_KEYCHAIN"),
    )


def handle_api(handler, *, paths: Paths, method: str, path: str, body: bytes | None) -> None:
    parsed = urlparse(path)
    route = parsed.path

    if route == "/api/entries" and method == "GET":
        return _entries(handler, paths, parsed.query)
    if route.startswith("/api/entries/") and method == "GET":
        entry_id = route.rsplit("/", 1)[-1]
        return _entry_detail(handler, paths, entry_id)
    if route == "/api/copy" and method == "POST":
        return _copy(handler, paths, body)
    if route == "/api/heartbeat" and method == "POST":
        handler._send_json(200, {"ok": True})
        return
    if route == "/api/shutdown" and method == "POST":
        # schedule a shutdown after responding
        handler._send_json(200, {"ok": True})
        threading.Thread(target=_shutdown_self, daemon=True).start()
        return
    if route == "/api/audit" and method == "GET":
        return _audit(handler, paths, parsed.query)

    handler._send_json(404, {"error": "not found"})


def _entries(handler, paths: Paths, query: str) -> None:
    store = MetadataStore(paths)
    entries = store.list()
    rev = reverse_refs(entries)
    out = []
    for e in entries:
        d = e.to_dict()
        d["used_by"] = rev.get(e.name, [])
        out.append(d)
    handler._send_json(200, {"entries": out})


def _entry_detail(handler, paths: Paths, entry_id: str) -> None:
    store = MetadataStore(paths)
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    rev = reverse_refs(store.list())
    d = e.to_dict()
    d["used_by"] = rev.get(e.name, [])
    # also inline last 5 audit events for this entry
    audit = AuditLog(paths)
    d["recent_events"] = list(audit.search(name=e.name, limit=5))
    handler._send_json(200, d)


def _copy(handler, paths: Paths, body: bytes) -> None:
    payload = json.loads(body or b"{}")
    entry_id = payload.get("id")
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_id(entry_id) if entry_id else None
    if e is None:
        handler._send_json(404, {"error": "entry not found"})
        return
    backend = _backend()
    try:
        value = backend.get(e.id)
    except Exception as ex:
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error=str(ex))
        handler._send_json(500, {"error": str(ex)})
        return
    proc = subprocess.run(["pbcopy"], input=value, text=True)
    if proc.returncode != 0:
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error="pbcopy failed")
        handler._send_json(500, {"error": "pbcopy failed"})
        return
    audit.record(op="copy", name=e.name, id_=e.id, success=True)
    written_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    threading.Thread(
        target=_clipboard_clear_after,
        args=(written_hash, 30),
        daemon=True,
    ).start()
    handler._send_json(200, {"ok": True})


def _clipboard_clear_after(written_hash: str, delay: int) -> None:
    time.sleep(delay)
    current = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout
    current_hash = hashlib.sha256(current.encode("utf-8")).hexdigest()
    if current_hash == written_hash:
        subprocess.run(["pbcopy"], input="", text=True)


def _audit(handler, paths: Paths, query: str) -> None:
    qs = parse_qs(query)
    op = qs.get("op", [None])[0]
    name = qs.get("name", [None])[0]
    limit = int(qs.get("limit", ["100"])[0])
    audit = AuditLog(paths)
    events = list(audit.search(op=op, name=name, limit=limit))
    handler._send_json(200, {"events": events})


def _shutdown_self() -> None:
    # graceful exit — the test server handles the actual stop via close
    time.sleep(0.05)
    os._exit(0)
```

> **Note:** `_shutdown_self` calls `os._exit(0)` because in production we want the whole `keys serve` process to exit. The test asserts the server stops responding within ~200ms; that path will hit `os._exit` and end the test process if the test isn't isolated. Wrap the shutdown test:

```python
def test_api_shutdown_stops_server(admin):
    # In production this os._exit's; we patch it for the test.
    import os as _os
    real_exit = _os._exit
    called = threading.Event()
    def fake_exit(_):
        called.set()
    _os._exit = fake_exit
    try:
        _post(admin, "/api/shutdown")
        assert called.wait(timeout=2)
    finally:
        _os._exit = real_exit
```

Update the test in step 1 to use this patched form.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_server_api.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/api.py tests/test_server_api.py
git commit -m "feat: admin JSON API (entries/copy/heartbeat/shutdown/audit)"
```

### Task 3.3: Templating setup — Jinja2 base template + static asset pipeline

**Files:**
- Create: `src/keys_keeper/templates/base.html`
- Create: `src/keys_keeper/templates/dashboard.html`
- Modify: `src/keys_keeper/pages.py`
- Modify: `src/keys_keeper/static/app.css`

- [ ] **Step 1: Port the design tokens from the canvas**

Copy the CSS variables block + base styles from `keys-keeper-admin-canvas.html` (lines 14-118 — the `:root` and `body` rules) into `src/keys_keeper/static/app.css`. Strip the React/canvas-specific styles (`.canvas`, `.stage`, `.browser-frame`, `.sidebar` etc.). Keep only the production-relevant rules: design tokens, body, .mono, scrollbar, and the page-level styles for the topbar, dashboard, entry rows, etc.

The full app.css will be ~600 lines — copy directly from the canvas, removing the canvas-chrome sections (`.canvas`, `.stage*`, `.browser-*`, `.sb-*`, `.sb-meta`, `.copy-button`, `.copy-toast` (keep `.app-toast` — that's the production toast, not the canvas one)).

Resulting structure of `app.css`:

```
:root tokens (dark theme defaults)
:root[data-accent="..."]  variants
:root[data-theme="light"]  light overrides
body, html, .mono, * box-sizing
.app-shell, .app-topbar, .app-brand, .app-nav, .app-cmdk-trigger, .app-actions
.btn variants
.app-content
.dash-toolbar, .search-input, .tag-rail, .tag-chip
.unified-table-head, .entry-row (locked: unified mode), .entry-row note column
.type-icon, type colours
.detail-shell, .detail-* (S2)
.modal-backdrop, .modal, .new-modal, type-cards (S3)
.bulk-shell, .bulk-split.horizontal (locked), .bulk-pane, .bulk-textarea-display, .bulk-preview-row, .bulk-savebar (S4)
.audit-shell, .charts-row, .chart-card, .bar-row, .audit-filters, .audit-table (S5)
.settings-shell, .settings-card, .kv-row, .curtain (S6)
.app-toast, .empty, .banner-error
scrollbar
```

- [ ] **Step 2: Write `src/keys_keeper/templates/base.html`**

```html
<!DOCTYPE html>
<html lang="en" data-theme="dark" data-accent="rust">
<head>
<meta charset="UTF-8">
<title>{% block title %}keys-keeper · admin{% endblock %}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;450;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<div class="app-shell" data-density="compact" data-palette="header">
  {% block topbar %}
  <div class="app-topbar">
    <div class="app-brand"><span class="glyph">K</span><span>keys-keeper</span></div>
    <div class="app-nav">
      <a href="/" class="{% if active_nav == 'dashboard' %}active{% endif %}">Dashboard</a>
      <a href="/audit" class="{% if active_nav == 'audit' %}active{% endif %}">Audit</a>
      <a href="/settings" class="{% if active_nav == 'settings' %}active{% endif %}">Settings</a>
    </div>
    <div class="app-spacer"></div>
    <div class="app-cmdk-trigger" id="cmdk-trigger">
      <span>Jump to entry…</span>
      <span class="kbd" style="margin-left:auto">⌘K</span>
    </div>
    <div class="app-actions">
      <a href="/paste" class="btn btn-ghost">Bulk import</a>
      <a href="/new" class="btn btn-primary">+ New</a>
    </div>
  </div>
  {% endblock %}
  {% block content %}{% endblock %}
</div>
<script>
(() => {
  const params = new URLSearchParams(location.search);
  const t = params.get('t');
  if (t) {
    sessionStorage.setItem('kk_token', t);
    history.replaceState({}, '', location.pathname);
  }
  window.KK_TOKEN = sessionStorage.getItem('kk_token') || '';
})();
</script>
<script src="/static/app.js"></script>
{% block extra_js %}{% endblock %}
</body>
</html>
```

- [ ] **Step 3: Write `src/keys_keeper/templates/dashboard.html`**

(See Task 3.4 for full content; for now stub with a "loading" div so the template loader can be wired up.)

```html
{% extends "base.html" %}
{% block content %}
<div class="dash-toolbar">
  <div class="search-input">
    <input id="search" placeholder="Search by name, tag, or note · / to focus" autofocus>
    <span class="kbd">/</span>
  </div>
</div>
<div id="entries-mount">Loading…</div>
{% endblock %}
```

- [ ] **Step 4: Update `src/keys_keeper/pages.py` to use Jinja2**

```python
"""Server-rendered HTML pages."""
from __future__ import annotations
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)


def render_dashboard(*, paths: Paths, token: str) -> str:
    return _env.get_template("dashboard.html").render(
        active_nav="dashboard",
        token=token,
    )


def render_entry_detail(*, paths: Paths, token: str, entry) -> str:
    return _env.get_template("entry_detail.html").render(
        active_nav="dashboard",
        token=token,
        entry=entry,
    )


def render_new_edit(*, paths: Paths, token: str, entry=None) -> str:
    return _env.get_template("new_edit.html").render(
        active_nav="dashboard",
        token=token,
        entry=entry,
    )


def render_bulk_paste(*, paths: Paths, token: str) -> str:
    return _env.get_template("bulk_paste.html").render(
        active_nav="dashboard", token=token,
    )


def render_audit(*, paths: Paths, token: str) -> str:
    return _env.get_template("audit.html").render(
        active_nav="audit", token=token,
    )


def render_settings(*, paths: Paths, token: str) -> str:
    return _env.get_template("settings.html").render(
        active_nav="settings", token=token,
    )
```

- [ ] **Step 5: Add template inclusion to packaging**

In `pyproject.toml`, ensure templates and static assets are bundled:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/keys_keeper"]

[tool.hatch.build.targets.wheel.force-include]
"src/keys_keeper/templates" = "keys_keeper/templates"
"src/keys_keeper/static" = "keys_keeper/static"
```

- [ ] **Step 6: Wire `keys serve` command**

Add to `src/keys_keeper/cli.py`:

```python
def cmd_serve(args: argparse.Namespace) -> int:
    from keys_keeper.server import AdminServer
    paths = Paths()
    paths.ensure()
    server = AdminServer(paths=paths, port=args.port, idle_timeout_sec=15 * 60)
    url = f"http://127.0.0.1:{args.port or 7777}/?t={server.token}"
    print(f"keys-keeper admin starting on {url}")
    if not args.no_open:
        subprocess.Popen(["open", url])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    return 0
```

In `build_parser()`:

```python
    sv = sub.add_parser("serve", help="run the local web admin")
    sv.add_argument("--port", type=int, default=7777)
    sv.add_argument("--no-open", action="store_true")
    sv.set_defaults(func=cmd_serve)
```

- [ ] **Step 7: Manual smoke test**

```bash
pip install -e ".[dev]"
keys serve --no-open
# in another terminal:
curl -s "http://127.0.0.1:7777/?t=$(grep -oE 't=[a-f0-9]+' <<<"$(open the printed URL)" | head -1)" -o /tmp/dashboard.html
# or just open the printed URL in a browser. The dashboard shows "Loading…" — that's expected at this stage.
```

- [ ] **Step 8: Commit**

```bash
git add src/keys_keeper/templates/ src/keys_keeper/static/ src/keys_keeper/pages.py src/keys_keeper/cli.py pyproject.toml
git commit -m "feat: Jinja2 templates + static assets + keys serve"
```

### Task 3.4: S1 Dashboard — locked variants (unified-table, comfortable rows)

**Files:**
- Modify: `src/keys_keeper/templates/dashboard.html`
- Modify: `src/keys_keeper/static/app.js`
- Create: `tests/test_server_pages.py`

- [ ] **Step 1: Write the failing test**

`tests/test_server_pages.py`:

```python
import threading
import time
import urllib.request
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.server import AdminServer


@pytest.fixture
def admin(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    paths = Paths()
    paths.ensure()
    server = AdminServer(paths=paths, port=0, idle_timeout_sec=60)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while server.bound_port == 0:
        time.sleep(0.01)
    yield server
    server.stop()


def _get(admin, path):
    req = urllib.request.Request(f"http://127.0.0.1:{admin.bound_port}{path}")
    req.add_header("Sec-Keys-Token", admin.token)
    return urllib.request.urlopen(req, timeout=2).read().decode("utf-8")


def _seed(monkeypatch, name, type_="api_key"):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    cli.main(["add", name, "--type", type_, "--stdin"])


def test_dashboard_returns_html_with_topbar(admin):
    body = _get(admin, "/")
    assert "<title>keys-keeper" in body
    assert "Dashboard" in body
    assert "Bulk import" in body


def test_dashboard_has_unified_table_markup(admin):
    body = _get(admin, "/")
    # The locked variant per ux-spec § 8.4 DIM 1 is unified-table
    assert "unified-table-head" in body or 'class="unified-table-head"' in body or 'data-grouping="unified"' in body


def test_dashboard_includes_search_and_palette_trigger(admin):
    body = _get(admin, "/")
    assert "search" in body.lower()
    assert "cmdk" in body.lower() or "⌘K" in body


def test_app_js_fetches_entries_with_token(admin):
    js = _get(admin, "/static/app.js")
    assert "fetch" in js or "XMLHttpRequest" in js
    assert "Sec-Keys-Token" in js or "kk_token" in js
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_server_pages.py -v`
Expected: missing markup assertions.

- [ ] **Step 3: Replace `src/keys_keeper/templates/dashboard.html`**

```html
{% extends "base.html" %}
{% block content %}
<div class="dash-toolbar">
  <div class="search-input" id="search-shell">
    <input id="search" placeholder="Search by name, tag, or note · / to focus" autofocus>
    <span class="kbd">/</span>
  </div>
</div>
<div class="tag-rail" id="tag-rail">
  <span class="label">FILTER</span>
  {# tags rendered dynamically by JS once entries load #}
</div>
<div class="app-content" id="dashboard-content">
  <div class="unified-table-head" data-grouping="unified">
    <span></span>
    <span>type</span>
    <span>name · tags</span>
    <span>note</span>
    <span>last access</span>
    <span></span>
  </div>
  <div id="entries-mount">Loading…</div>
</div>
{% endblock %}
```

- [ ] **Step 4: Replace `src/keys_keeper/static/app.js` with dashboard logic**

```javascript
// keys-keeper admin client
(() => {
  const TOKEN = window.KK_TOKEN;

  async function api(path, opts = {}) {
    opts.headers = { ...(opts.headers || {}), 'Sec-Keys-Token': TOKEN };
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error(`${path}: ${r.status}`);
    return r.json();
  }

  const TYPE_META = {
    api_key: { short: 'AP', color: 'var(--type-api)' },
    ssh_key: { short: 'SSH', color: 'var(--type-ssh)' },
    server:  { short: 'SV', color: 'var(--type-server)' },
    domain:  { short: 'DM', color: 'var(--type-domain)' },
    note:    { short: 'NT', color: 'var(--type-note)' },
  };

  const state = {
    entries: [],
    activeTags: new Set(),
    search: '',
  };

  function relTime(iso) {
    const t = new Date(iso).getTime();
    const ago = Math.max(0, Date.now() - t);
    const m = Math.floor(ago / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m} min ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h} hr ago`;
    const d = Math.floor(h / 24);
    return `${d} d ago`;
  }

  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === 'class') e.className = v;
      else if (k === 'onclick') e.onclick = v;
      else e.setAttribute(k, v);
    });
    children.flat().forEach(c => e.append(c instanceof Node ? c : document.createTextNode(c ?? '')));
    return e;
  }

  function render() {
    const mount = document.getElementById('entries-mount');
    mount.innerHTML = '';
    const filtered = state.entries.filter(e => {
      if (state.search && !(`${e.name} ${(e.tags || []).join(' ')} ${e.note || ''}`.toLowerCase().includes(state.search.toLowerCase()))) {
        return false;
      }
      if (state.activeTags.size > 0 && !(e.tags || []).some(t => state.activeTags.has(t))) {
        return false;
      }
      return true;
    });
    if (filtered.length === 0) {
      mount.append(el('div', { class: 'empty', style: 'padding:40px;text-align:center;color:var(--text-3)' }, 'No matches'));
      return;
    }
    filtered.forEach(e => mount.append(rowEl(e)));
  }

  function rowEl(e) {
    const meta = TYPE_META[e.type] || { short: '?', color: 'var(--text-3)' };
    const row = el('div', { class: 'entry-row unified' });
    row.append(
      el('span', {
        class: 'type-icon',
        style: `background:${meta.color};width:22px;height:22px;font-size:10px;display:inline-flex;align-items:center;justify-content:center;border-radius:5px;color:var(--bg);font-weight:700`,
      }, meta.short),
      el('span', { class: 'type-label-mono' }, e.type),
      (() => {
        const c = el('div', { class: 'name-block' });
        const r1 = el('div', { class: 'row', style: 'gap:10px;flex-wrap:wrap' });
        r1.append(el('span', { class: 'name' }, e.name));
        const taglist = el('div', { class: 'tag-mini-list' });
        (e.tags || []).slice(0, 4).forEach(t => taglist.append(el('span', { class: 'tag-mini' }, t)));
        r1.append(taglist);
        c.append(r1);
        return c;
      })(),
      el('span', { class: 'note-preview', style: 'margin:0;max-width:100%' }, e.note || (e.fields?.host ? `${e.fields.user || ''}@${e.fields.host}` : '')),
      el('span', { class: 'last-access' }, e.updated_at ? relTime(e.updated_at) : ''),
      (() => {
        const a = el('div', { class: 'actions' });
        const copyBtn = el('button', {
          class: 'icon-btn',
          title: 'Copy to clipboard',
          onclick: (ev) => { ev.stopPropagation(); copy(e.id, e.name); },
        }, '📋');
        const editBtn = el('a', { class: 'icon-btn', href: `/entry/${encodeURIComponent(e.id)}`, title: 'Open' }, '↗');
        a.append(copyBtn, editBtn);
        return a;
      })(),
    );
    row.onclick = () => { location.href = `/entry/${encodeURIComponent(e.id)}`; };
    return row;
  }

  async function copy(id, name) {
    try {
      await api('/api/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
      toast(`Copied ${name} · auto-clear in 30s`);
    } catch (ex) {
      toast(`Copy failed: ${ex.message}`, 'error');
    }
  }

  function toast(msg, kind = 'success') {
    const t = el('div', { class: 'app-toast' }, msg);
    if (kind === 'error') t.style.borderColor = 'var(--danger)';
    document.body.append(t);
    setTimeout(() => t.remove(), 3500);
  }

  function renderTagRail() {
    const rail = document.getElementById('tag-rail');
    if (!rail) return;
    const allTags = new Set();
    state.entries.forEach(e => (e.tags || []).forEach(t => allTags.add(t)));
    rail.querySelectorAll('.tag-chip').forEach(n => n.remove());
    [...allTags].sort().forEach(t => {
      const chip = el('span', {
        class: 'tag-chip' + (state.activeTags.has(t) ? ' active' : ''),
        onclick: () => {
          if (state.activeTags.has(t)) state.activeTags.delete(t);
          else state.activeTags.add(t);
          renderTagRail();
          render();
        },
      }, t);
      rail.append(chip);
    });
  }

  async function load() {
    const data = await api('/api/entries');
    state.entries = data.entries;
    renderTagRail();
    render();
  }

  document.getElementById('search').addEventListener('input', (e) => {
    state.search = e.target.value;
    render();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
      e.preventDefault();
      document.getElementById('search')?.focus();
    }
    if (e.key === 'Escape') {
      const s = document.getElementById('search');
      if (s) s.value = '';
      state.search = '';
      state.activeTags.clear();
      renderTagRail();
      render();
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      document.getElementById('search')?.focus();
    }
  });

  setInterval(() => {
    fetch('/api/heartbeat', { method: 'POST', headers: { 'Sec-Keys-Token': TOKEN } });
  }, 60000);

  window.addEventListener('beforeunload', () => {
    navigator.sendBeacon('/api/shutdown');
  });

  load().catch(err => {
    document.getElementById('entries-mount').textContent = `Failed to load: ${err.message}`;
  });
})();
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `pytest tests/test_server_pages.py -v`
Expected: 4 passed.

- [ ] **Step 6: Manual smoke test**

```bash
keys add canvas-test-1 --type api_key --stdin <<<"v"
keys add canvas-test-2 --type server --from-file /dev/null --field host=1.2.3.4 --field user=root --field auth=ssh_key
keys serve
# browser auto-opens; verify dashboard renders unified-table with both entries.
# search "canvas" → filters. `/` focuses search. tag chip click filters.
```

- [ ] **Step 7: Commit**

```bash
git add src/keys_keeper/templates/ src/keys_keeper/static/ tests/test_server_pages.py
git commit -m "feat: S1 Dashboard — unified-table + search/filter/copy"
```

### Task 3.5: Cmd+K palette (navigation-only)

**Files:**
- Modify: `src/keys_keeper/templates/base.html`
- Modify: `src/keys_keeper/static/app.js`

- [ ] **Step 1: Append palette markup to `base.html` after `app-shell` close**

Insert before the closing `</body>`:

```html
<div id="cmdk-overlay" hidden>
  <div class="cmdk-modal">
    <input id="cmdk-input" placeholder="Jump to entry · type to filter" autocomplete="off">
    <div id="cmdk-results"></div>
    <div class="cmdk-footer">
      <span class="kbd">↑↓</span> navigate <span class="kbd">↵</span> open <span class="kbd">Esc</span> close
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add palette CSS to `app.css`**

```css
#cmdk-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; align-items: flex-start; justify-content: center; padding-top: 18vh; z-index: 100; }
#cmdk-overlay[hidden] { display: none; }
.cmdk-modal { width: 580px; background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 8px; box-shadow: var(--shadow-lg); overflow: hidden; }
#cmdk-input { width: 100%; padding: 14px 18px; background: transparent; border: none; outline: none; color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 14px; border-bottom: 1px solid var(--border-subtle); }
#cmdk-results { max-height: 400px; overflow-y: auto; }
.cmdk-row { display: flex; align-items: center; gap: 12px; padding: 9px 18px; cursor: pointer; font-family: 'JetBrains Mono', monospace; font-size: 12.5px; }
.cmdk-row.selected, .cmdk-row:hover { background: var(--surface-hover); }
.cmdk-row .type-icon { width: 18px; height: 18px; font-size: 9px; }
.cmdk-footer { padding: 7px 18px; font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: var(--text-4); border-top: 1px solid var(--border-subtle); }
```

- [ ] **Step 3: Add palette logic to `app.js` (append to the IIFE)**

```javascript
  // -- command palette --
  const palette = {
    open: false,
    query: '',
    selectedIdx: 0,
    items: [],
  };

  function paletteOpen() {
    palette.open = true;
    palette.query = '';
    palette.selectedIdx = 0;
    document.getElementById('cmdk-overlay').hidden = false;
    document.getElementById('cmdk-input').value = '';
    document.getElementById('cmdk-input').focus();
    paletteRender();
  }
  function paletteClose() {
    palette.open = false;
    document.getElementById('cmdk-overlay').hidden = true;
  }
  function paletteRender() {
    const q = palette.query.toLowerCase();
    palette.items = state.entries
      .filter(e => !q || e.name.toLowerCase().includes(q) || (e.tags || []).some(t => t.toLowerCase().includes(q)))
      .slice(0, 20);
    if (palette.selectedIdx >= palette.items.length) palette.selectedIdx = Math.max(0, palette.items.length - 1);
    const r = document.getElementById('cmdk-results');
    r.innerHTML = '';
    palette.items.forEach((e, i) => {
      const meta = TYPE_META[e.type] || {};
      const row = el('div', {
        class: 'cmdk-row' + (i === palette.selectedIdx ? ' selected' : ''),
        onclick: () => { paletteClose(); location.href = `/entry/${encodeURIComponent(e.id)}`; },
      });
      row.append(
        el('span', { class: 'type-icon', style: `background:${meta.color};color:var(--bg);font-weight:700;display:inline-flex;align-items:center;justify-content:center;border-radius:4px` }, meta.short || '?'),
        el('span', { class: 'name', style: 'flex:1' }, e.name),
        el('span', { style: 'color:var(--text-3);font-size:11px' }, e.type),
      );
      r.append(row);
    });
  }

  document.getElementById('cmdk-input').addEventListener('input', (e) => {
    palette.query = e.target.value;
    palette.selectedIdx = 0;
    paletteRender();
  });
  document.getElementById('cmdk-input').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); palette.selectedIdx = Math.min(palette.items.length - 1, palette.selectedIdx + 1); paletteRender(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); palette.selectedIdx = Math.max(0, palette.selectedIdx - 1); paletteRender(); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const sel = palette.items[palette.selectedIdx];
      if (sel) { paletteClose(); location.href = `/entry/${encodeURIComponent(sel.id)}`; }
    }
    else if (e.key === 'Escape') { e.preventDefault(); paletteClose(); }
  });

  document.getElementById('cmdk-trigger')?.addEventListener('click', paletteOpen);

  // global Cmd+K
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      paletteOpen();
    }
  });
```

- [ ] **Step 4: Manual smoke test**

```bash
keys serve
# Cmd+K opens palette · type to filter · arrows + Enter to open · Esc closes
```

- [ ] **Step 5: Commit**

```bash
git add src/keys_keeper/templates/base.html src/keys_keeper/static/
git commit -m "feat: Cmd+K command palette (navigation-only)"
```

---

## Phase 4 — Admin CRUD

### Task 4.1: S2 Entry detail page

**Files:**
- Create: `src/keys_keeper/templates/entry_detail.html`
- Modify: `src/keys_keeper/server.py` (add /entry/:id route)
- Modify: `src/keys_keeper/pages.py` (already has render_entry_detail stub)
- Modify: `tests/test_server_pages.py` (add detail tests)

- [ ] **Step 1: Add the route in `server.py`**

In the `do_GET` body, add before the `/static/` branch:

```python
            if path.startswith("/entry/"):
                entry_id = path[len("/entry/"):]
                from keys_keeper.pages import render_entry_detail
                from keys_keeper.store import MetadataStore
                store = MetadataStore(paths)
                e = store.get_by_id(entry_id) or store.get_by_name(entry_id)
                if e is None:
                    self._send(404, b"entry not found")
                    return
                html = render_entry_detail(paths=paths, token=admin.token, entry=e)
                self._send(200, html.encode("utf-8"))
                return
```

- [ ] **Step 2: Write `src/keys_keeper/templates/entry_detail.html`**

```html
{% extends "base.html" %}
{% block content %}
<div class="detail-shell" id="detail-mount" data-entry-id="{{ entry.id }}">
  <div class="detail-main">
    <div class="detail-header">
      <span class="type-badge" style="background:var(--type-{{ entry.type.value if entry.type.value else entry.type }}-soft, var(--surface-2));">{{ entry.type.value if entry.type.value else entry.type }}</span>
      <span class="last-access mono" style="color:var(--text-3);font-size:11px">id: {{ entry.id }}</span>
    </div>
    <h1 class="detail-name" id="entry-name">{{ entry.name }}</h1>
    <div class="detail-tags" id="detail-tags"></div>
    <div class="detail-action-bar">
      <button class="btn btn-primary" id="copy-btn">Copy value</button>
      <a class="btn" href="/entry/{{ entry.id }}/edit">Edit</a>
      <button class="btn btn-ghost" id="replace-secret-btn">Replace secret</button>
      <div style="flex:1"></div>
      <button class="btn btn-danger btn-sm" id="delete-btn">Delete</button>
    </div>
    <div id="fields-mount"></div>
    <div id="refs-mount"></div>
    <div class="field-section">
      <div class="field-section-title">Notes</div>
      <div style="padding:8px 0;font-size:13px;color:var(--text-2);line-height:1.55">{{ entry.note or '—' }}</div>
    </div>
  </div>
  <div class="detail-side">
    <div class="field-section-title">Recent access</div>
    <div id="recent-mount" class="mini-audit">Loading…</div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: Write detail-page client logic**

Append to `src/keys_keeper/static/app.js` (inside the IIFE — it can co-exist with the dashboard logic; route off the page DOM):

```javascript
  if (document.getElementById('detail-mount')) {
    const id = document.getElementById('detail-mount').dataset.entryId;
    api(`/api/entries/${encodeURIComponent(id)}`).then(e => {
      // tags
      const tagsEl = document.getElementById('detail-tags');
      (e.tags || []).forEach(t => tagsEl.append(el('span', { class: 'tag-mini' }, t)));
      // fields
      const fm = document.getElementById('fields-mount');
      const sec = el('div', { class: 'field-section' });
      sec.append(el('div', { class: 'field-section-title' }, 'Fields'));
      Object.entries(e.fields || {}).forEach(([k, v]) => {
        const r = el('div', { class: 'field-row' });
        r.append(el('span', { class: 'key' }, k), el('span', { class: 'value' }, String(v)), el('span'));
        sec.append(r);
      });
      fm.append(sec);
      // refs
      const rm = document.getElementById('refs-mount');
      if ((e.refs || []).length || (e.used_by || []).length) {
        const r = el('div', { class: 'field-section' });
        r.append(el('div', { class: 'field-section-title' }, 'Linked entries'));
        (e.refs || []).forEach(ref => {
          const item = el('a', { class: 'refs-item', href: `/entry/${encodeURIComponent(ref.name)}` });
          item.append(
            el('span', { class: 'role' }, ref.role),
            el('div', { class: 'target' }, el('span', { class: 'name' }, ref.name)),
            el('span', { class: 'arrow' }, '→'),
          );
          r.append(item);
        });
        if ((e.used_by || []).length) {
          r.append(el('div', { class: 'field-section-title', style: 'margin-top:14px' }, 'Used by'));
          e.used_by.forEach(name => {
            const item = el('a', { class: 'refs-item', href: `/entry/${encodeURIComponent(name)}` });
            item.append(el('span', { class: 'role' }, 'used by'), el('div', { class: 'target' }, el('span', { class: 'name' }, name)), el('span', { class: 'arrow' }, '→'));
            r.append(item);
          });
        }
        rm.append(r);
      }
      // recent events
      const audit = document.getElementById('recent-mount');
      audit.innerHTML = '';
      (e.recent_events || []).forEach(ev => {
        const row = el('div', { class: 'mini-audit-row' });
        row.append(
          el('span', { class: 'ts' }, relTime(ev.ts)),
          el('span', { class: `op-tag op-${ev.op}` }, ev.op),
          el('span', { class: 'ctx' }, ev.file_target || ev.caller_path || ''),
        );
        audit.append(row);
      });

      document.getElementById('copy-btn').onclick = () => copy(e.id, e.name);
      document.getElementById('delete-btn').onclick = async () => {
        if (!confirm(`Delete ${e.name}?`)) return;
        await api(`/api/entries/${encodeURIComponent(e.id)}`, { method: 'DELETE' });
        location.href = '/';
      };
    });
  }
```

- [ ] **Step 4: Add DELETE handler to API**

In `src/keys_keeper/api.py` `handle_api`, add before the 404:

```python
    if route.startswith("/api/entries/") and method == "DELETE":
        entry_id = route.rsplit("/", 1)[-1]
        store = MetadataStore(paths)
        audit = AuditLog(paths)
        e = store.get_by_id(entry_id) or store.get_by_name(entry_id)
        if e is None:
            handler._send_json(404, {"error": "not found"})
            return
        # check refs
        deps = [x for x in store.list() if any(r.get("name") == e.name for r in x.refs)]
        if deps:
            handler._send_json(409, {
                "error": "has dependents",
                "dependents": [d.name for d in deps],
            })
            return
        store.delete_by_name(e.name)
        backend = _backend()
        backend.delete(e.id)
        backend.delete(e.id + ":passphrase")
        audit.record(op="delete", name=e.name, id_=e.id, success=True)
        handler._send_json(200, {"ok": True})
        return
```

- [ ] **Step 5: Add route handling for DELETE in `server.py`**

Add a `do_DELETE` method:

```python
        def do_DELETE(self) -> None:
            admin.heartbeat()
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            from keys_keeper.api import handle_api
            handle_api(self, paths=paths, method="DELETE", path=urlparse(self.path).path, body=None)
```

- [ ] **Step 6: Add tests**

Append to `tests/test_server_pages.py`:

```python
def test_entry_detail_renders(admin, monkeypatch):
    _seed(monkeypatch, "detail-target")
    body = _get(admin, f"/entry/detail-target")
    assert "detail-target" in body
    assert "Copy value" in body
    assert "Linked entries" in body or "fields-mount" in body
```

Append to `tests/test_server_api.py`:

```python
def test_api_delete_entry(admin, monkeypatch):
    _seed(monkeypatch, "to-del")
    entries = json.loads(_get(admin, "/api/entries").read())["entries"]
    eid = next(e["id"] for e in entries if e["name"] == "to-del")
    req = urllib.request.Request(
        f"http://127.0.0.1:{admin.bound_port}/api/entries/{eid}",
        method="DELETE",
    )
    req.add_header("Sec-Keys-Token", admin.token)
    urllib.request.urlopen(req).read()
    after = json.loads(_get(admin, "/api/entries").read())["entries"]
    assert all(e["name"] != "to-del" for e in after)
```

- [ ] **Step 7: Run tests and commit**

```bash
pytest tests/test_server_pages.py tests/test_server_api.py -v
git add src/keys_keeper/ tests/
git commit -m "feat: S2 entry detail page + DELETE API"
```

### Task 4.2: S3 New / Edit form (server-rendered + JS submit)

**Files:**
- Create: `src/keys_keeper/templates/new_edit.html`
- Modify: `src/keys_keeper/server.py` (add /new and /entry/:id/edit routes)
- Modify: `src/keys_keeper/api.py` (POST /api/entries, PATCH /api/entries/:id)

- [ ] **Step 1: Add server routes**

In `server.py` `do_GET`:

```python
            if path == "/new":
                from keys_keeper.pages import render_new_edit
                self._send(200, render_new_edit(paths=paths, token=admin.token).encode("utf-8"))
                return
            if path.startswith("/entry/") and path.endswith("/edit"):
                from keys_keeper.pages import render_new_edit
                from keys_keeper.store import MetadataStore
                eid = path[len("/entry/"):-len("/edit")]
                e = MetadataStore(paths).get_by_id(eid) or MetadataStore(paths).get_by_name(eid)
                if e is None:
                    self._send(404, b"entry not found")
                    return
                self._send(200, render_new_edit(paths=paths, token=admin.token, entry=e).encode("utf-8"))
                return
```

- [ ] **Step 2: Write `src/keys_keeper/templates/new_edit.html`**

```html
{% extends "base.html" %}
{% block content %}
<div class="modal-backdrop" style="position:static;background:transparent;align-items:flex-start;padding:24px">
  <div class="modal new-modal" style="margin:0 auto" data-edit-id="{{ entry.id if entry else '' }}">
    <div class="modal-header">
      <span class="modal-title">{% if entry %}Edit {{ entry.name }}{% else %}New entry{% endif %}</span>
    </div>
    <div class="type-cards" id="type-cards">
      {% for t in ['api_key', 'ssh_key', 'server', 'domain', 'note'] %}
      <div class="type-card {% if (entry and entry.type.value == t) or (not entry and t == 'api_key') %}selected{% endif %}" data-type="{{ t }}">
        <div class="icon-large" style="background:var(--type-{{ t.split('_')[0] }})">{{ t[:2]|upper }}</div>
        <div class="label">{{ t }}</div>
      </div>
      {% endfor %}
    </div>
    <div class="form-fields" id="form-fields">
      <div class="form-row">
        <span class="label">name <span class="req">*</span></span>
        <input class="text-input" id="f-name" value="{{ entry.name if entry else '' }}" {% if entry %}readonly{% endif %}>
      </div>
      <div id="type-specific-fields"></div>
      <div class="form-row">
        <span class="label">tags</span>
        <input class="text-input" id="f-tags" placeholder="comma-separated" value="{{ ','.join(entry.tags) if entry else '' }}">
      </div>
      <div class="form-row">
        <span class="label">note</span>
        <textarea class="textarea-input" id="f-note">{{ entry.note if entry else '' }}</textarea>
      </div>
    </div>
    <div class="modal-footer">
      <span style="flex:1;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-3)"><span class="kbd">⌘ Enter</span> save</span>
      <a class="btn btn-ghost" href="{% if entry %}/entry/{{ entry.id }}{% else %}/{% endif %}">Cancel</a>
      <button class="btn btn-primary" id="save-btn">Save entry</button>
    </div>
    <div id="form-error" style="padding:0 18px 12px;color:var(--danger);font-family:'JetBrains Mono',monospace;font-size:11px"></div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: Add new/edit form JS to app.js**

```javascript
  if (document.querySelector('.new-modal')) {
    const modal = document.querySelector('.new-modal');
    const editId = modal.dataset.editId;
    let selectedType = document.querySelector('.type-card.selected')?.dataset.type || 'api_key';
    let editingEntry = null;

    if (editId) {
      api(`/api/entries/${encodeURIComponent(editId)}`).then(e => {
        editingEntry = e;
        renderTypeFields();
      });
    } else {
      renderTypeFields();
    }

    document.querySelectorAll('.type-card').forEach(card => {
      card.onclick = () => {
        if (editId) return;
        document.querySelectorAll('.type-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        selectedType = card.dataset.type;
        renderTypeFields();
      };
    });

    function renderTypeFields() {
      const c = document.getElementById('type-specific-fields');
      c.innerHTML = '';
      const e = editingEntry;
      if (selectedType === 'api_key') {
        c.append(formRow('service', 'service', e?.fields?.service || '', false));
        if (!editId) c.append(secretRow('value', 'paste secret value · stays out of the DOM after submit', true));
      } else if (selectedType === 'ssh_key') {
        c.append(formRow('public_key', 'public key', e?.fields?.public_key || '', true));
        if (!editId) c.append(secretRow('private_key', 'paste private key (multi-line OK)', true));
        c.append(formRow('comment', 'comment', e?.fields?.comment || '', false));
      } else if (selectedType === 'server') {
        c.append(formRow('host', 'host', e?.fields?.host || '', true));
        c.append(formRow('port', 'port', e?.fields?.port || '22', false));
        c.append(formRow('user', 'user', e?.fields?.user || '', true));
        c.append(formRow('auth', 'auth', e?.fields?.auth || 'ssh_key', true));
        c.append(formRow('ssh_key_ref', 'ssh_key ref', e?.refs?.find(r => r.role === 'ssh_key')?.name || '', false));
      } else if (selectedType === 'domain') {
        c.append(formRow('host', 'host', e?.fields?.host || '', true));
        c.append(formRow('registrar', 'registrar', e?.fields?.registrar || '', false));
      } else if (selectedType === 'note') {
        c.append(formRow('body', 'body', e?.fields?.body || '', false));
      }
    }

    function formRow(name, label, val, req) {
      const r = document.createElement('div'); r.className = 'form-row';
      const lbl = document.createElement('span'); lbl.className = 'label'; lbl.textContent = label; if (req) lbl.innerHTML += ' <span class="req">*</span>';
      const inp = document.createElement('input'); inp.className = 'text-input'; inp.id = `f-${name}`; inp.value = val;
      r.append(lbl, inp); return r;
    }
    function secretRow(name, placeholder, multiline) {
      const r = document.createElement('div'); r.className = 'form-row';
      const lbl = document.createElement('span'); lbl.className = 'label'; lbl.innerHTML = `${name} <span class="req">*</span>`;
      const inp = document.createElement(multiline ? 'textarea' : 'input');
      inp.className = multiline ? 'textarea-input' : 'text-input';
      inp.id = `f-${name}`;
      inp.placeholder = placeholder;
      if (multiline) inp.rows = 3;
      r.append(lbl, inp); return r;
    }

    async function save() {
      const errEl = document.getElementById('form-error');
      errEl.textContent = '';
      const payload = {
        name: document.getElementById('f-name').value.trim(),
        type: selectedType,
        tags: document.getElementById('f-tags').value.split(',').map(s => s.trim()).filter(Boolean),
        note: document.getElementById('f-note').value,
        fields: {},
        refs: [],
      };
      ['service', 'public_key', 'comment', 'host', 'port', 'user', 'auth', 'registrar', 'body'].forEach(k => {
        const el = document.getElementById(`f-${k}`);
        if (el) {
          let v = el.value.trim();
          if (k === 'port' && v) v = parseInt(v);
          if (v) payload.fields[k] = v;
        }
      });
      const refEl = document.getElementById('f-ssh_key_ref');
      if (refEl?.value.trim()) payload.refs.push({ role: 'ssh_key', name: refEl.value.trim() });
      const valueEl = document.getElementById('f-value') || document.getElementById('f-private_key');
      if (valueEl) payload.value = valueEl.value;

      try {
        if (editId) {
          await api(`/api/entries/${encodeURIComponent(editId)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          location.href = `/entry/${encodeURIComponent(editId)}`;
        } else {
          const r = await api('/api/entries', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          location.href = `/entry/${encodeURIComponent(r.id)}`;
        }
      } catch (ex) {
        errEl.textContent = ex.message;
      }
    }

    document.getElementById('save-btn').onclick = save;
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); save(); }
    });
  }
```

- [ ] **Step 4: Add POST and PATCH handlers in `api.py`**

```python
    if route == "/api/entries" and method == "POST":
        return _create_entry(handler, paths, body)
    if route.startswith("/api/entries/") and method == "PATCH":
        entry_id = route.rsplit("/", 1)[-1]
        return _patch_entry(handler, paths, entry_id, body)
```

```python
def _create_entry(handler, paths: Paths, body: bytes) -> None:
    payload = json.loads(body or b"{}")
    from keys_keeper.models import Entry, EntryType, ValidationError
    try:
        type_ = EntryType(payload["type"])
        e = Entry.new(
            name=payload["name"],
            type=type_,
            fields=payload.get("fields", {}),
            tags=payload.get("tags", []),
            note=payload.get("note", ""),
            refs=payload.get("refs", []),
        )
    except (ValidationError, KeyError, ValueError) as ex:
        handler._send_json(400, {"error": str(ex)})
        return
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = _backend()
    try:
        store.add(e)
    except Exception as ex:
        handler._send_json(409, {"error": str(ex)})
        return
    if payload.get("value"):
        backend.set(e.id, payload["value"])
    audit.record(op="add", name=e.name, id_=e.id, success=True)
    handler._send_json(201, {"id": e.id, "name": e.name})


def _patch_entry(handler, paths: Paths, entry_id: str, body: bytes) -> None:
    payload = json.loads(body or b"{}")
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    if "tags" in payload:
        e.tags = list(payload["tags"])
    if "note" in payload:
        e.note = payload["note"]
    if "fields" in payload:
        e.fields = {**e.fields, **payload["fields"]}
    if "refs" in payload:
        e.refs = list(payload["refs"])
    from keys_keeper.models import _now_iso
    e.updated_at = _now_iso()
    store.update(e)
    if payload.get("value"):
        _backend().set(e.id, payload["value"])
    audit.record(op="update", name=e.name, id_=e.id, success=True)
    handler._send_json(200, {"ok": True})
```

- [ ] **Step 5: Wire PATCH into server**

Add `do_PATCH` to `server.py`:

```python
        def do_PATCH(self) -> None:
            admin.heartbeat()
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            from keys_keeper.api import handle_api
            handle_api(self, paths=paths, method="PATCH", path=urlparse(self.path).path, body=body)
```

- [ ] **Step 6: Manual smoke test**

```bash
keys serve
# / → click "+ New" → fill name + secret → save → redirected to detail
# Edit → toggle tags / note → save → reflected
```

- [ ] **Step 7: Commit**

```bash
git add src/keys_keeper/templates/new_edit.html src/keys_keeper/server.py src/keys_keeper/api.py src/keys_keeper/static/app.js
git commit -m "feat: S3 New/Edit form + POST/PATCH API"
```

### Task 4.3: Bulk-paste parser

**Files:**
- Create: `src/keys_keeper/parser.py`
- Create: `tests/test_parser.py`

- [ ] **Step 1: Write the failing test**

`tests/test_parser.py`:

```python
import pytest
from keys_keeper.parser import parse_bulk, ParsedEntry, ParseError


def test_parse_simple_equals():
    src = "openrouter-cline = sk-or-v1-abc"
    rows = parse_bulk(src)
    assert len(rows) == 1
    assert rows[0].name == "openrouter-cline"
    assert rows[0].value == "sk-or-v1-abc"
    assert rows[0].type == "api_key"
    assert rows[0].tags == []
    assert rows[0].error is None


def test_parse_colon_separator():
    rows = parse_bulk("foo: bar")
    assert rows[0].value == "bar"


def test_parse_with_inline_tags():
    rows = parse_bulk("k1 = v1 [llm,personal]")
    assert rows[0].tags == ["llm", "personal"]


def test_parse_with_explicit_type():
    rows = parse_bulk("my-key (ssh_key) = something")
    assert rows[0].type == "ssh_key"


def test_parse_skips_comments_and_blanks():
    src = "# comment\n\nfoo = bar\n# another\n"
    rows = parse_bulk(src)
    assert len(rows) == 1
    assert rows[0].name == "foo"


def test_parse_multiline_triple_quote():
    src = '''my-pem (ssh_key) = """
-----BEGIN PRIVATE KEY-----
linetwo
-----END-----
"""'''
    rows = parse_bulk(src)
    assert len(rows) == 1
    assert "BEGIN PRIVATE KEY" in rows[0].value
    assert "linetwo" in rows[0].value
    assert rows[0].type == "ssh_key"


def test_parse_unclosed_multiline_is_error():
    src = 'my-pem = """\nline1\n'
    rows = parse_bulk(src)
    assert rows[0].error is not None
    assert "unclosed" in rows[0].error.lower() or "multiline" in rows[0].error.lower()


def test_parse_invalid_name_recorded_as_error():
    rows = parse_bulk("Bad Name = v")
    assert rows[0].error is not None


def test_parse_returns_line_numbers():
    src = "a = 1\nb = 2\n"
    rows = parse_bulk(src)
    assert rows[0].line == 1
    assert rows[1].line == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_parser.py -v`
Expected: ImportError on `keys_keeper.parser`.

- [ ] **Step 3: Write `src/keys_keeper/parser.py`**

```python
"""Parser for the bulk paste format.

Grammar (line-oriented, with multi-line values via triple-quote):
  line          = blank | comment | entry
  blank         = whitespace-only
  comment       = "#" rest-of-line
  entry         = name [ "(" type ")" ] sep value [ "[" tags "]" ]
  sep           = "=" | ":"
  value         = single-line-string | triple-quoted-block
  triple-quote  = '"""' newline ... '"""'
  tags          = comma-separated identifiers
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Iterator
from keys_keeper.models import validate_name, ValidationError, EntryType


@dataclass
class ParsedEntry:
    line: int
    name: str
    type: str
    value: str
    tags: list[str] = field(default_factory=list)
    error: str | None = None


class ParseError(RuntimeError):
    pass


_HEADER_RE = re.compile(
    r"""^
    (?P<name>[a-z0-9][a-z0-9._-]*[a-z0-9]) \s*
    (?: \( (?P<type>[a-z_]+) \) \s* )?
    (?P<sep>[=:])
    \s*
    (?P<value>.*?)
    \s*
    (?: \[ (?P<tags>[^\]]+) \] \s* )?
    $""",
    re.VERBOSE,
)


def parse_bulk(text: str) -> list[ParsedEntry]:
    out: list[ParsedEntry] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Detect multi-line: line ends with `= """` or `: """`.
        m_open = re.match(
            r"""^
            (?P<name>[a-z0-9A-Z][\w.-]*[a-z0-9A-Z]) \s*
            (?: \( (?P<type>[a-z_]+) \) \s* )?
            [=:]
            \s* \"\"\" \s* $""",
            raw, re.VERBOSE,
        )
        if m_open:
            name = m_open.group("name")
            type_ = m_open.group("type") or _guess_type(name, "")
            buf: list[str] = []
            j = i + 1
            closed = False
            tags: list[str] = []
            while j < len(lines):
                line_raw = lines[j]
                m_close = re.match(r'^\s*"""(?:\s*\[\s*([^\]]+)\s*\])?\s*$', line_raw)
                if m_close:
                    if m_close.group(1):
                        tags = [t.strip() for t in m_close.group(1).split(",") if t.strip()]
                    closed = True
                    break
                buf.append(line_raw)
                j += 1
            entry = ParsedEntry(
                line=i + 1,
                name=name,
                type=type_,
                value="\n".join(buf),
                tags=tags,
            )
            try:
                validate_name(name)
                EntryType(type_)
            except (ValidationError, ValueError) as ex:
                entry.error = str(ex)
            if not closed:
                entry.error = "unclosed multiline block (missing closing \"\"\")"
            out.append(entry)
            i = j + 1 if closed else len(lines)
            continue

        # Single-line entry
        m = _HEADER_RE.match(raw)
        if not m:
            out.append(ParsedEntry(line=i + 1, name="?", type="?", value="", error="unparseable line"))
            i += 1
            continue
        name = m.group("name")
        explicit_type = m.group("type")
        value = m.group("value")
        tags = [t.strip() for t in (m.group("tags") or "").split(",") if t.strip()]
        type_ = explicit_type or _guess_type(name, value)
        entry = ParsedEntry(line=i + 1, name=name, type=type_, value=value, tags=tags)
        try:
            validate_name(name)
            EntryType(type_)
        except (ValidationError, ValueError) as ex:
            entry.error = str(ex)
        out.append(entry)
        i += 1
    return out


def _guess_type(name: str, value: str) -> str:
    if value.startswith("ssh-") or "BEGIN OPENSSH" in value or "BEGIN RSA" in value:
        return "ssh_key"
    if "." in name and not value:
        return "domain"
    return "api_key"
```

- [ ] **Step 4: Run tests + commit**

```bash
pytest tests/test_parser.py -v
git add src/keys_keeper/parser.py tests/test_parser.py
git commit -m "feat: bulk-paste parser with multiline + tags + type override"
```

### Task 4.4: S4 Bulk paste page (split-horizontal locked)

**Files:**
- Create: `src/keys_keeper/templates/bulk_paste.html`
- Modify: `src/keys_keeper/server.py` (add /paste route)
- Modify: `src/keys_keeper/api.py` (POST /api/bulk-import)
- Modify: `src/keys_keeper/static/app.js` (bulk page logic)

- [ ] **Step 1: Add server route**

In `server.py` `do_GET`, add:

```python
            if path == "/paste":
                from keys_keeper.pages import render_bulk_paste
                self._send(200, render_bulk_paste(paths=paths, token=admin.token).encode("utf-8"))
                return
```

- [ ] **Step 2: Write `src/keys_keeper/templates/bulk_paste.html`**

```html
{% extends "base.html" %}
{% block content %}
<div class="bulk-shell" id="bulk-shell">
  <div class="bulk-header">
    <span class="h1"><span class="crumb">/paste</span> Bulk import</span>
    <a class="format-link" id="format-toggle">format reference ↓</a>
  </div>
  <div id="format-help" hidden style="padding:10px 24px;background:var(--surface);border-bottom:1px solid var(--border-subtle);font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.7;color:var(--text-2)"><strong>Grammar:</strong>  <code>name [(type)] = value [tags]</code> · separators <code>=</code> or <code>:</code> · multi-line via <code>"""...."""</code> · <code>#</code> = comment.</div>
  <div class="bulk-split horizontal">
    <div class="bulk-pane">
      <div class="bulk-pane-header"><span>SOURCE</span><span id="line-count">0 lines</span></div>
      <textarea class="bulk-textarea" id="bulk-input" placeholder="# OpenRouter
openrouter-cline = sk-or-v1-...
openrouter-roo: sk-or-v1-... [llm,personal]

# Multi-line SSH key
my-key (ssh_key) = &quot;&quot;&quot;
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
&quot;&quot;&quot; [personal,do]"></textarea>
    </div>
    <div class="bulk-pane">
      <div class="bulk-pane-header"><span>PREVIEW</span><span id="preview-count">0 entries · 0 errors</span></div>
      <div class="bulk-preview-table" id="preview-table">
        <div class="bulk-preview-row header">
          <span></span><span>#</span><span>name</span><span>type</span><span>value · tags</span><span></span><span></span>
        </div>
        <div id="preview-rows"></div>
      </div>
    </div>
  </div>
  <div class="bulk-savebar">
    <span class="summary" id="bulk-summary">Paste content to begin</span>
    <div class="row gap-4">
      <a class="btn btn-ghost" href="/">Cancel</a>
      <button class="btn btn-primary" id="bulk-save" disabled>Save all</button>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: Bulk page JS**

Append to `app.js`:

```javascript
  if (document.getElementById('bulk-shell')) {
    const input = document.getElementById('bulk-input');
    const rowsEl = document.getElementById('preview-rows');
    let lastParse = [];

    document.getElementById('format-toggle').onclick = () => {
      const h = document.getElementById('format-help');
      h.hidden = !h.hidden;
    };

    let timer = null;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(parsePreview, 200);
    });

    async function parsePreview() {
      const text = input.value;
      document.getElementById('line-count').textContent = `${text.split('\n').length} lines`;
      const r = await api('/api/bulk-import?dry-run=1', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: text }),
      });
      lastParse = r.rows;
      renderPreview(r.rows);
      const errs = r.rows.filter(r => r.error).length;
      document.getElementById('preview-count').textContent = `${r.rows.length} entries · ${errs} errors`;
      document.getElementById('bulk-summary').textContent = errs > 0
        ? `${r.rows.length - errs} ready · ${errs} error${errs > 1 ? 's' : ''} blocking save`
        : `Will save ${r.rows.length} entries · 0 errors`;
      const btn = document.getElementById('bulk-save');
      btn.disabled = (r.rows.length === 0 || errs > 0);
    }

    function renderPreview(rows) {
      rowsEl.innerHTML = '';
      rows.forEach(r => {
        const row = el('div', { class: 'bulk-preview-row' + (r.error ? ' error' : '') });
        row.append(
          el('span', { class: 'status-dot' }),
          el('span', { class: 'row-num' }, String(r.line)),
          el('span', { class: 'name' }, r.name),
          (() => {
            const sel = document.createElement('select');
            sel.className = 'type-dropdown';
            ['api_key', 'ssh_key', 'server', 'domain', 'note'].forEach(t => {
              const opt = document.createElement('option');
              opt.value = t; opt.textContent = t;
              if (t === r.type) opt.selected = true;
              sel.append(opt);
            });
            sel.onchange = () => { r.type = sel.value; };
            return sel;
          })(),
          el('span', { class: 'summary' },
            el('span', { class: 'muted' }, r.value.includes('\n') ? `${r.value.split('\n').length} lines` : `${r.value.length} chars`),
            ' ',
            el('span', { style: 'color:var(--type-domain)' }, r.tags.length ? `[${r.tags.join(',')}]` : ''),
          ),
          el('span', { class: 'muted', style: 'font-size:10px' }, '↗ line'),
          el('span'),
        );
        rowsEl.append(row);
        if (r.error) {
          rowsEl.append(el('div', { class: 'bulk-error-detail' },
            el('span', { class: 'line-no' }, `line ${r.line}:`),
            ' ',
            r.error,
          ));
        }
      });
    }

    document.getElementById('bulk-save').onclick = async () => {
      const r = await api('/api/bulk-import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: input.value, rows: lastParse }),
      });
      if (r.ok) {
        location.href = '/';
      } else {
        alert(`Import failed: ${r.error}`);
      }
    };
  }
```

- [ ] **Step 4: API endpoint**

Add to `api.py`:

```python
    if route == "/api/bulk-import" and method == "POST":
        return _bulk_import(handler, paths, parsed.query, body)
```

```python
def _bulk_import(handler, paths: Paths, query: str, body: bytes) -> None:
    from keys_keeper.parser import parse_bulk
    from keys_keeper.models import Entry, EntryType, ValidationError
    payload = json.loads(body or b"{}")
    text = payload.get("source", "")
    dry = "dry-run=1" in (query or "")
    rows = parse_bulk(text)

    # serialize for response
    out = [{
        "line": r.line,
        "name": r.name,
        "type": r.type,
        "value": r.value,
        "tags": r.tags,
        "error": r.error,
    } for r in rows]

    if dry:
        handler._send_json(200, {"rows": out})
        return

    if any(r.error for r in rows):
        handler._send_json(400, {"error": "rows have errors", "rows": out})
        return

    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = _backend()
    # validate name collisions BEFORE any write
    existing = {e.name for e in store.list()}
    collisions = [r.name for r in rows if r.name in existing]
    if collisions:
        handler._send_json(409, {"error": "name collisions", "names": collisions})
        return
    # write all
    for r in rows:
        type_ = EntryType(r.type)
        fields: dict = {}
        if type_ == EntryType.SSH_KEY and not r.value.startswith("-----"):
            # the parsed multiline IS the private key body; store accordingly
            pass
        try:
            entry = Entry.new(name=r.name, type=type_, fields=fields, tags=r.tags)
        except ValidationError as ex:
            handler._send_json(500, {"error": f"row {r.line}: {ex}"})
            return
        store.add(entry)
        if type_ in (EntryType.API_KEY, EntryType.SSH_KEY) or (type_ == EntryType.NOTE):
            backend.set(entry.id, r.value)
        audit.record(op="add", name=entry.name, id_=entry.id, success=True)
    handler._send_json(200, {"ok": True, "imported": len(rows)})
```

- [ ] **Step 5: Manual smoke test**

```bash
keys serve
# / → "Bulk import" → paste a few lines → preview updates → Save all → all imported
```

- [ ] **Step 6: Commit**

```bash
git add src/keys_keeper/templates/bulk_paste.html src/keys_keeper/server.py src/keys_keeper/api.py src/keys_keeper/static/app.js
git commit -m "feat: S4 Bulk paste with live preview + atomic import"
```

### Task 4.5: Replace-secret inline flow

**Files:**
- Modify: `src/keys_keeper/templates/entry_detail.html` (already wired in 4.1; add modal markup)
- Modify: `src/keys_keeper/static/app.js`
- Modify: `src/keys_keeper/api.py` (POST /api/entries/:id/replace-secret)

- [ ] **Step 1: Add replace-secret modal markup at the end of `entry_detail.html`**

```html
<div class="modal-backdrop" id="replace-modal" hidden>
  <div class="modal" style="width:480px">
    <div class="modal-header">
      <span class="modal-title">Replace secret value</span>
      <button class="icon-btn" id="rm-cancel">×</button>
    </div>
    <div class="modal-body">
      <p style="margin-top:0;font-size:12.5px">Paste the new value below. The old value is overwritten in keychain. The DOM never stores the value after submit.</p>
      <textarea id="rm-input" class="textarea-input" rows="4" placeholder="Paste new secret value"></textarea>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" id="rm-cancel-2">Cancel</button>
      <button class="btn btn-primary" id="rm-save">Replace</button>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Wire JS in `app.js` (extend the detail-mount block)**

```javascript
    document.getElementById('replace-secret-btn').onclick = () => {
      document.getElementById('replace-modal').hidden = false;
      document.getElementById('rm-input').value = '';
      document.getElementById('rm-input').focus();
    };
    document.getElementById('rm-cancel').onclick = () =>
      document.getElementById('replace-modal').hidden = true;
    document.getElementById('rm-cancel-2').onclick = () =>
      document.getElementById('replace-modal').hidden = true;
    document.getElementById('rm-save').onclick = async () => {
      const inp = document.getElementById('rm-input');
      const val = inp.value;
      inp.value = '';  // wipe DOM immediately
      try {
        await api(`/api/entries/${encodeURIComponent(id)}/replace-secret`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ value: val }),
        });
        document.getElementById('replace-modal').hidden = true;
        toast('Secret replaced');
      } catch (ex) {
        toast(`Replace failed: ${ex.message}`, 'error');
      }
    };
```

- [ ] **Step 3: API endpoint**

Add to `api.py`:

```python
    if route.startswith("/api/entries/") and route.endswith("/replace-secret") and method == "POST":
        entry_id = route[len("/api/entries/"):-len("/replace-secret")]
        return _replace_secret(handler, paths, entry_id, body)
```

```python
def _replace_secret(handler, paths: Paths, entry_id: str, body: bytes) -> None:
    payload = json.loads(body or b"{}")
    value = payload.get("value")
    if not value:
        handler._send_json(400, {"error": "value required"})
        return
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    backend = _backend()
    backend.set(e.id, value)
    from keys_keeper.models import _now_iso
    e.updated_at = _now_iso()
    store.update(e)
    audit.record(op="replace_secret", name=e.name, id_=e.id, success=True)
    handler._send_json(200, {"ok": True})
```

- [ ] **Step 4: Manual smoke + commit**

```bash
keys serve
# entry detail → Replace secret → paste → save → toast confirms; old value gone from keychain
git add src/keys_keeper/templates/entry_detail.html src/keys_keeper/api.py src/keys_keeper/static/app.js
git commit -m "feat: replace-secret flow with DOM wipe"
```

### Task 4.6: Cmd+K integration with refs (cross-page navigation)

**Files:**
- Modify: `src/keys_keeper/static/app.js`

- [ ] **Step 1: On non-dashboard pages, fetch entries for the palette**

The dashboard logic already loads entries into `state.entries`. On the entry detail / new-edit / bulk pages, the palette never gets populated. Fix it: lazily fetch when palette opens if `state.entries` is empty.

Update `paletteOpen()`:

```javascript
  async function paletteOpen() {
    palette.open = true;
    palette.query = '';
    palette.selectedIdx = 0;
    document.getElementById('cmdk-overlay').hidden = false;
    document.getElementById('cmdk-input').value = '';
    document.getElementById('cmdk-input').focus();
    if (state.entries.length === 0) {
      try {
        const r = await api('/api/entries');
        state.entries = r.entries;
      } catch {}
    }
    paletteRender();
  }
```

- [ ] **Step 2: Manual smoke + commit**

```bash
# on /entry/<id>, hit Cmd+K, palette populates
git add src/keys_keeper/static/app.js
git commit -m "feat: palette auto-loads entries on non-dashboard pages"
```

---

## Phase 5 — Audit + Settings

### Task 5.1: S5 Audit page (locked: bar chart style)

**Files:**
- Create: `src/keys_keeper/templates/audit.html`
- Modify: `src/keys_keeper/server.py` (add /audit route)
- Modify: `src/keys_keeper/static/app.js` (audit page logic + SVG charts)

- [ ] **Step 1: Add server route**

```python
            if path == "/audit":
                from keys_keeper.pages import render_audit
                self._send(200, render_audit(paths=paths, token=admin.token).encode("utf-8"))
                return
```

- [ ] **Step 2: Write `src/keys_keeper/templates/audit.html`**

```html
{% extends "base.html" %}
{% block content %}
<div class="audit-shell" id="audit-shell">
  <div class="charts-row">
    <div class="chart-card" id="chart-top">
      <div class="chart-title"><span>Top entries · last 7 d</span><span class="meta">by access count</span></div>
      <div id="top-bars">Loading…</div>
    </div>
    <div class="chart-card" id="chart-daily">
      <div class="chart-title"><span>Daily activity · last 30 d</span><span class="meta" id="daily-total"></span></div>
      <div id="daily-svg"></div>
    </div>
    <div class="chart-card" id="chart-ops">
      <div class="chart-title"><span>Op-type · last 7 d</span><span class="meta" id="ops-total"></span></div>
      <div id="ops-bars"></div>
    </div>
  </div>
  <div class="audit-filters" id="audit-filters">
    <div class="group">
      <span class="group-label">RANGE</span>
      <button class="preset-btn" data-range="24h">24h</button>
      <button class="preset-btn active" data-range="7d">7d</button>
      <button class="preset-btn" data-range="30d">30d</button>
    </div>
    <div class="group">
      <span class="group-label">OPS</span>
      <span class="tag-chip op-filter" data-op="inject">inject</span>
      <span class="tag-chip op-filter" data-op="copy">copy</span>
      <span class="tag-chip op-filter" data-op="resolve">resolve</span>
      <span class="tag-chip op-filter" data-op="reveal">reveal</span>
      <span class="tag-chip op-filter" data-op="add">add</span>
      <span class="tag-chip op-filter" data-op="delete">delete</span>
    </div>
  </div>
  <div style="background:var(--surface);border:1px solid var(--border-subtle);border-radius:6px;overflow:hidden;margin-top:12px">
    <table class="audit-table">
      <thead><tr><th>Timestamp</th><th>Op</th><th>Name</th><th>Caller</th><th>File</th><th>OK</th></tr></thead>
      <tbody id="audit-rows"><tr><td colspan="6">Loading…</td></tr></tbody>
    </table>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: Audit page JS**

Append to `app.js`:

```javascript
  if (document.getElementById('audit-shell')) {
    const filters = { ops: new Set(), range: '7d' };

    function rangeSeconds(r) {
      return { '24h': 86400, '7d': 604800, '30d': 2592000 }[r] || 604800;
    }

    document.querySelectorAll('.preset-btn').forEach(b => {
      b.onclick = () => {
        document.querySelectorAll('.preset-btn').forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        filters.range = b.dataset.range;
        load();
      };
    });
    document.querySelectorAll('.op-filter').forEach(c => {
      c.onclick = () => {
        c.classList.toggle('active');
        if (filters.ops.has(c.dataset.op)) filters.ops.delete(c.dataset.op);
        else filters.ops.add(c.dataset.op);
        load();
      };
    });

    async function load() {
      const all = (await api('/api/audit?limit=2000')).events;
      const cutoff = (Date.now() - rangeSeconds(filters.range) * 1000);
      const inRange = all.filter(e => new Date(e.ts).getTime() >= cutoff);
      const filtered = filters.ops.size === 0
        ? inRange
        : inRange.filter(e => filters.ops.has(e.op));

      // top entries
      const counts = {};
      inRange.forEach(e => { counts[e.name] = (counts[e.name] || 0) + 1; });
      const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
      const max = Math.max(...top.map(([, c]) => c), 1);
      const topEl = document.getElementById('top-bars');
      topEl.innerHTML = '';
      top.forEach(([name, c]) => {
        const r = el('div', { class: 'bar-row' });
        r.append(
          el('span', { class: 'name' }, name),
          el('span', { class: 'bar-track' }, el('span', { class: 'bar-fill', style: `width:${c / max * 100}%` })),
          el('span', { class: 'num' }, String(c)),
        );
        topEl.append(r);
      });

      // daily activity (locked: bar style)
      const days = Array(30).fill(0);
      const now = Date.now();
      all.forEach(e => {
        const t = new Date(e.ts).getTime();
        const dayIdx = Math.floor((now - t) / 86400000);
        if (dayIdx >= 0 && dayIdx < 30) days[29 - dayIdx]++;
      });
      const dmax = Math.max(...days, 1);
      let svg = `<svg viewBox="0 0 300 120" preserveAspectRatio="none" style="height:120px;width:100%">`;
      days.forEach((v, i) => {
        const w = 300 / 30;
        const h = (v / dmax) * 110;
        svg += `<rect x="${i * w + 1}" y="${120 - h}" width="${w - 2}" height="${h}" fill="var(--accent)" fill-opacity="0.85"/>`;
      });
      svg += `<line x1="0" y1="119" x2="300" y2="119" stroke="var(--border-subtle)" stroke-width="0.5"/></svg>`;
      document.getElementById('daily-svg').innerHTML = svg;
      document.getElementById('daily-total').textContent = `${days.reduce((s, v) => s + v, 0)} events`;

      // op-type distribution
      const opCounts = {};
      inRange.forEach(e => { opCounts[e.op] = (opCounts[e.op] || 0) + 1; });
      const opPairs = Object.entries(opCounts).sort((a, b) => b[1] - a[1]);
      const opMax = Math.max(...opPairs.map(([, c]) => c), 1);
      const opsEl = document.getElementById('ops-bars');
      opsEl.innerHTML = '';
      opPairs.forEach(([op, c]) => {
        const r = el('div', { class: 'bar-row' });
        r.append(
          el('span', { class: 'name' }, op),
          el('span', { class: 'bar-track' }, el('span', { class: 'bar-fill', style: `width:${c / opMax * 100}%` })),
          el('span', { class: 'num' }, String(c)),
        );
        opsEl.append(r);
      });
      document.getElementById('ops-total').textContent = `${inRange.length} ops`;

      // table
      const tbody = document.getElementById('audit-rows');
      tbody.innerHTML = '';
      filtered.slice(0, 200).forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="ts">${relTime(e.ts)}</td>
          <td><span class="op-tag op-${e.op}" style="padding:1px 7px;border-radius:3px;font-size:10px">${e.op}</span></td>
          <td class="name"><a href="/entry/${encodeURIComponent(e.name)}">${e.name}</a></td>
          <td class="caller">${e.caller_path || ''}</td>
          <td class="file">${e.file_target || '—'}</td>
          <td class="${e.success ? 'ok' : 'fail'}">${e.success ? '✓' : '✗'}</td>`;
        tbody.append(tr);
      });
    }

    load();
  }
```

- [ ] **Step 4: Manual smoke + commit**

```bash
# generate some audit events first:
keys add audit-test --type api_key --stdin <<<"v"
keys copy audit-test
keys serve
# /audit shows charts with the events
git add src/keys_keeper/templates/audit.html src/keys_keeper/server.py src/keys_keeper/static/app.js
git commit -m "feat: S5 Audit page with bar charts"
```

### Task 5.2: S6 Settings page

**Files:**
- Create: `src/keys_keeper/templates/settings.html`
- Modify: `src/keys_keeper/server.py` (add /settings route)
- Modify: `src/keys_keeper/api.py` (GET /api/status)
- Modify: `src/keys_keeper/static/app.js` (settings logic)

- [ ] **Step 1: Add server route**

```python
            if path == "/settings":
                from keys_keeper.pages import render_settings
                self._send(200, render_settings(paths=paths, token=admin.token).encode("utf-8"))
                return
```

- [ ] **Step 2: Status endpoint in `api.py`**

```python
    if route == "/api/status" and method == "GET":
        return _status(handler, paths)
```

```python
def _status(handler, paths: Paths) -> None:
    import os, time
    from keys_keeper import __version__
    info = {
        "version": __version__,
        "config_dir": str(paths.root),
        "data_json": str(paths.data_json),
        "audit_jsonl": str(paths.audit_jsonl),
        "reveal_env_set": os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") == "1",
        "uptime_sec": int(time.monotonic() - getattr(handler.server, "_kk_started", time.monotonic())),
    }
    handler._send_json(200, info)
```

(Set `_kk_started` on the server in `AdminServer.serve_forever`: `self._server._kk_started = time.monotonic()`.)

- [ ] **Step 3: Write `src/keys_keeper/templates/settings.html`**

```html
{% extends "base.html" %}
{% block content %}
<div class="settings-shell">
  <div style="font-family:'JetBrains Mono',monospace;font-size:22px;font-weight:600">Settings</div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-3);margin-top:2px">Server status, security, and maintenance</div>
  <div class="settings-grid">
    <div class="settings-card" id="card-status">
      <div class="card-title">Server status</div>
      <div id="status-body">Loading…</div>
    </div>
    <div class="settings-card" id="card-security">
      <div class="card-title">Security</div>
      <div id="security-body">Loading…</div>
    </div>
    <div class="settings-card full" id="card-maintenance">
      <div class="card-title">Maintenance</div>
      <div class="row gap-4" style="justify-content:space-between">
        <div style="flex:1">
          <div style="font-family:'JetBrains Mono',monospace;font-weight:500;margin-bottom:4px">Shutdown server</div>
          <div style="font-size:11.5px;color:var(--text-3)">Stops the admin immediately. Re-run <span class="mono" style="color:var(--accent)">keys serve</span> to restart.</div>
        </div>
        <button class="btn btn-danger" id="shutdown-btn">Shutdown now</button>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Settings JS**

```javascript
  if (document.querySelector('.settings-shell')) {
    api('/api/status').then(s => {
      document.getElementById('status-body').innerHTML = `
        <div class="kv-row"><span class="key">version</span><span class="val">${s.version}</span></div>
        <div class="kv-row"><span class="key">port</span><span class="val">${location.port}</span></div>
        <div class="kv-row"><span class="key">uptime</span><span class="val">${Math.floor(s.uptime_sec / 60)} min ${s.uptime_sec % 60} s</span></div>
        <div class="kv-row"><span class="key">config_dir</span><span class="val mono">${s.config_dir}</span></div>
      `;
      document.getElementById('security-body').innerHTML = `
        <div class="kv-row"><span class="key">KEYS_KEEPER_ALLOW_REVEAL</span><span class="val ${s.reveal_env_set ? 'success' : 'danger'}">${s.reveal_env_set ? '✓ set' : '✗ not set'}</span></div>
        <div class="kv-row"><span class="key">URL token</span><span class="val success">✓ active · stripped from history</span></div>
        ${s.reveal_env_set ? '' : `
        <div style="margin-top:14px;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:5px;font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.6">
          <div style="color:var(--text-4);margin-bottom:4px"># add to ~/.zshrc to enable</div>
          <div style="color:var(--accent)">export KEYS_KEEPER_ALLOW_REVEAL=1</div>
        </div>`}
      `;
    });

    document.getElementById('shutdown-btn').onclick = async () => {
      if (!confirm('Shutdown the server now?')) return;
      await api('/api/shutdown', { method: 'POST' });
      document.body.innerHTML = '<div class="curtain"><div class="glyph">K</div><div class="title">Server stopped</div><div class="sub">Re-run <span class="mono">keys serve</span> to restart.</div></div>';
    };
  }
```

- [ ] **Step 5: Manual smoke + commit**

```bash
keys serve
# /settings shows real status. shutdown button stops the server.
git add src/keys_keeper/templates/settings.html src/keys_keeper/server.py src/keys_keeper/api.py src/keys_keeper/static/app.js
git commit -m "feat: S6 Settings + status API + shutdown button"
```

---

## Phase 6 — Backup / export

### Task 6.1: `keys export` — AES-256-GCM with PBKDF2

**Files:**
- Create: `src/keys_keeper/crypto.py`
- Create: `tests/test_crypto.py`
- Modify: `src/keys_keeper/cli.py`
- Create: `tests/test_cli_export.py`

- [ ] **Step 1: Write the failing test for crypto**

`tests/test_crypto.py`:

```python
import pytest
from keys_keeper.crypto import encrypt_blob, decrypt_blob, BadPassword


def test_round_trip():
    data = b"hello world"
    sealed = encrypt_blob(data, password="pwd123")
    out = decrypt_blob(sealed, password="pwd123")
    assert out == data


def test_wrong_password_fails():
    sealed = encrypt_blob(b"x", password="right")
    with pytest.raises(BadPassword):
        decrypt_blob(sealed, password="wrong")


def test_format_includes_version_byte():
    sealed = encrypt_blob(b"x", password="p")
    assert sealed[:4] == b"KK1\x00"  # magic + version
```

- [ ] **Step 2: Write `src/keys_keeper/crypto.py`**

```python
"""AES-256-GCM with PBKDF2-HMAC-SHA256 for keys-keeper export blobs.

File format (binary):
  4 bytes : magic "KK1\\0"  (version byte = 0)
  16 bytes : salt
  12 bytes : nonce
  N bytes  : ciphertext + 16-byte GCM tag (combined by AESGCM)
"""
from __future__ import annotations
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class BadPassword(RuntimeError):
    pass


_MAGIC = b"KK1\x00"
_KDF_ITERATIONS = 600_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_blob(data: bytes, *, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, data, _MAGIC)
    return _MAGIC + salt + nonce + ct


def decrypt_blob(blob: bytes, *, password: str) -> bytes:
    if blob[:4] != _MAGIC:
        raise BadPassword("not a keys-keeper export blob")
    salt = blob[4:20]
    nonce = blob[20:32]
    ct = blob[32:]
    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, _MAGIC)
    except Exception as ex:
        raise BadPassword("password incorrect or file corrupted") from ex
```

- [ ] **Step 3: Write `keys export` / `keys import` CLI commands**

Append to `cli.py`:

```python
import getpass

def cmd_export(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    backend = _backend()
    audit = AuditLog(paths)
    pw = getpass.getpass("Export password: ")
    pw2 = getpass.getpass("Confirm: ")
    if pw != pw2:
        sys.stderr.write("passwords do not match\n")
        return 1
    payload = {
        "schema_version": 1,
        "entries": [],
    }
    for e in store.list():
        rec = e.to_dict()
        # collect secrets for this entry
        rec["_secret"] = None
        rec["_secret_passphrase"] = None
        try:
            rec["_secret"] = backend.get(e.id)
        except Exception:
            pass
        try:
            rec["_secret_passphrase"] = backend.get(e.id + ":passphrase")
        except Exception:
            pass
        payload["entries"].append(rec)
    from keys_keeper.crypto import encrypt_blob
    blob = encrypt_blob(json.dumps(payload).encode("utf-8"), password=pw)
    Path(args.file).write_bytes(blob)
    audit.record(op="export", name="<all>", id_="-", file_target=args.file, success=True)
    print(f"exported {len(payload['entries'])} entries to {args.file}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from keys_keeper.crypto import decrypt_blob, BadPassword
    paths = Paths()
    paths.ensure()
    pw = getpass.getpass("Import password: ")
    blob = Path(args.file).read_bytes()
    try:
        raw = decrypt_blob(blob, password=pw)
    except BadPassword as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    payload = json.loads(raw)
    store = MetadataStore(paths)
    backend = _backend()
    audit = AuditLog(paths)
    existing = {e.name for e in store.list()}
    imported = 0
    for rec in payload["entries"]:
        secret = rec.pop("_secret", None)
        passphrase = rec.pop("_secret_passphrase", None)
        from keys_keeper.models import Entry
        e = Entry.from_dict(rec)
        if e.name in existing:
            if args.replace:
                store.replace_by_name(e)
            else:
                continue
        else:
            store.add(e)
        if secret:
            backend.set(e.id, secret)
        if passphrase:
            backend.set(e.id + ":passphrase", passphrase)
        imported += 1
    audit.record(op="import", name="<all>", id_="-", file_target=args.file, success=True)
    print(f"imported {imported} entries")
    return 0
```

In `build_parser()`:

```python
    ex = sub.add_parser("export", help="encrypted backup to file")
    ex.add_argument("file")
    ex.set_defaults(func=cmd_export)

    im = sub.add_parser("import", help="restore from encrypted backup")
    im.add_argument("file")
    im.add_argument("--replace", action="store_true", help="overwrite existing names")
    im.add_argument("--merge", action="store_true", help="(default) skip name collisions")
    im.set_defaults(func=cmd_import)
```

- [ ] **Step 4: Test for round-trip export/import**

`tests/test_cli_export.py`:

```python
import pytest
from io import StringIO
from unittest.mock import patch
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def test_export_then_import_round_trip(cli_env, tmp_path, monkeypatch):
    # seed
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    cli.main(["add", "exp1", "--type", "api_key", "--stdin"])
    monkeypatch.setattr("sys.stdin", StringIO("v2\n"))
    cli.main(["add", "exp2", "--type", "api_key", "--stdin"])

    out_file = tmp_path / "backup.kk"

    # export
    with patch("getpass.getpass", side_effect=["password123", "password123"]):
        cli.main(["export", str(out_file)])
    assert out_file.exists()
    assert out_file.stat().st_size > 32

    # wipe and import
    cli.main(["rm", "exp1"])
    cli.main(["rm", "exp2"])
    assert MetadataStore(Paths()).get_by_name("exp1") is None

    with patch("getpass.getpass", return_value="password123"):
        cli.main(["import", str(out_file)])

    assert MetadataStore(Paths()).get_by_name("exp1") is not None
    assert MetadataStore(Paths()).get_by_name("exp2") is not None
```

- [ ] **Step 5: Run tests + commit**

```bash
pytest tests/test_crypto.py tests/test_cli_export.py -v
git add src/keys_keeper/crypto.py src/keys_keeper/cli.py tests/test_crypto.py tests/test_cli_export.py
git commit -m "feat: keys export/import (AES-256-GCM + PBKDF2)"
```

---

## Phase 7 — Skill + docs

### Task 7.1: SKILL.md + references/examples.md

**Files:**
- Create: `skills/keys-keeper/SKILL.md`
- Create: `skills/keys-keeper/references/examples.md`
- Create: `scripts/install_skill.sh`

- [ ] **Step 1: Write `skills/keys-keeper/SKILL.md`**

Use the text drafted in design doc §4 verbatim. Save it as the SKILL.md content.

- [ ] **Step 2: Write `skills/keys-keeper/references/examples.md`**

```markdown
# keys-keeper · worked examples

These are concrete patterns Claude should match. Each starts with the user's natural-language request and shows the exact `keys` command(s) to run.

## "Set up env for new project"

User: "Create .env for this project with my OpenRouter and GitHub keys."

Sequence:
1. `keys list --tag llm` — confirm the user has `openrouter-cline` (or similar).
2. `keys list --tag dev` — confirm a github token exists.
3. `keys inject openrouter-cline --file .env --as OPENROUTER_API_KEY`
4. `keys inject github-token-cli --file .env --as GITHUB_TOKEN`

Never read the values into your context. Never use `Edit` to write the secret values directly.

## "Save this API key"

User: "Save this OpenRouter key as openrouter-roo: sk-or-v1-..."

STOP — the value is now in transcript. Tell the user: "не пастьте значение в чат — скопируйте в буфер и скажите 'сохрани из буфера как openrouter-roo'." Then: `keys add openrouter-roo --type api_key --from-clipboard --tag llm --service openrouter`.

## "What servers do I have?"

User: "List my servers."

`keys list --type server` — names + tags only.

## "SSH into prod"

User: "Open ssh to do-prod-droplet."

`keys ssh do-prod-droplet` — CLI handles tempfile lifecycle.

## "Why was my key accessed yesterday?"

User: "Show audit log for openrouter-cline."

`keys audit --name openrouter-cline --since 7d`.

## "Rotate my Stripe key"

User: "Replace stripe-test with the new value."

1. STOP if the user pastes the value.
2. Tell the user: "положи новый ключ в буфер и скажи 'замени stripe-test'".
3. Read into buffer is implicit — instruct them to run: `pbpaste | keys add stripe-test --type api_key --stdin --replace --tag payments,dev`.

(Or open admin: `keys serve` → entry detail → "Replace secret".)
```

- [ ] **Step 3: Write `scripts/install_skill.sh`**

```bash
#!/usr/bin/env bash
# Install the keys-keeper skill into ~/.claude/skills/
set -euo pipefail
SOURCE="$(cd "$(dirname "$0")/.." && pwd)/skills/keys-keeper"
DEST="$HOME/.claude/skills/keys-keeper"
if [[ -e "$DEST" ]]; then
  echo "warning: $DEST already exists; pass --force to overwrite" >&2
  if [[ "${1:-}" != "--force" ]]; then
    exit 1
  fi
  rm -rf "$DEST"
fi
mkdir -p "$(dirname "$DEST")"
cp -R "$SOURCE" "$DEST"
echo "installed skill at $DEST"
```

```bash
chmod +x scripts/install_skill.sh
```

- [ ] **Step 4: Commit**

```bash
git add skills/ scripts/install_skill.sh
git commit -m "feat: SKILL.md + examples.md + install script"
```

### Task 7.2: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

```markdown
# keys-keeper

Personal macOS-first secrets manager for one developer who runs many AI agents and many servers. Stores API keys, SSH keys, server credentials, and domain info in the macOS Keychain, with a Claude skill that prevents secret values from ever entering an agent's transcript.

**Status:** v0.1 — single-user, macOS only.

## Install

```bash
pipx install /path/to/keys-keeper
keys doctor                              # creates ~/.config/keys-keeper/, probes keychain
echo 'export KEYS_KEEPER_ALLOW_REVEAL=1' >> ~/.zshrc   # optional, lets shell users print plaintext
./scripts/install_skill.sh               # copies the Claude skill
```

## Quick start

```bash
# save a secret without typing the value into an AI chat
pbcopy <<<"sk-or-v1-..."
keys add openrouter-cline --type api_key --from-clipboard --tag llm

# get it into a file
keys inject openrouter-cline --file .env --as OPENROUTER_API_KEY

# open the local admin to browse 50+ entries
keys serve
```

## Output-safe command surface

| For Claude (safe) | For shell (gated) |
|---|---|
| `keys add NAME --from-clipboard` | `keys reveal NAME` (requires `KEYS_KEEPER_ALLOW_REVEAL=1`) |
| `keys list / info / audit` | |
| `keys copy NAME` (clipboard, auto-clear 30s) | |
| `keys inject NAME --file F --as ENV` | |
| `keys resolve FILE` (substitute `__KEYS:name__`) | |
| `keys ssh NAME` | |

The skill markdown forbids Claude from running `reveal`. The CLI default surface is built so even a misbehaving agent can't extract plaintext into the transcript.

## See also

- [`docs/superpowers/specs/2026-05-04-keys-keeper-design.md`](docs/superpowers/specs/2026-05-04-keys-keeper-design.md) — full design
- [`ux-spec-2026-05-04-keys-keeper-admin.md`](ux-spec-2026-05-04-keys-keeper-admin.md) — admin UX spec
- [`keys-keeper-admin-canvas.html`](keys-keeper-admin-canvas.html) — interactive design canvas

## License

Private project. No license granted.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README"
```

---

## Phase 8 — Polish + ship

### Task 8.1: Light theme tokens

**Files:**
- Modify: `src/keys_keeper/static/app.css`
- Modify: `src/keys_keeper/templates/base.html` (theme toggle in settings)

- [ ] **Step 1: Verify the canvas's `:root[data-theme="light"]` block is in `app.css`**

If it's already ported from Task 3.3 — done. If not, add:

```css
:root[data-theme="light"] {
  --bg: #fafaf9;
  --bg-elevated: #ffffff;
  --surface: #ffffff;
  --surface-2: #f4f4f3;
  --surface-hover: #ececea;
  --border: #d8d8d6;
  --border-subtle: #e8e8e6;
  --border-strong: #b8b8b6;
  --text: #161718;
  --text-2: #555960;
  --text-3: #808488;
  --text-4: #b0b3b8;
}
```

- [ ] **Step 2: Add theme toggle to settings page**

Insert into `settings.html` (under Security card or as a new card):

```html
<div class="settings-card">
  <div class="card-title">Appearance</div>
  <div class="kv-row"><span class="key">theme</span>
    <span class="val">
      <button class="preset-btn" data-theme="dark">dark</button>
      <button class="preset-btn" data-theme="light">light</button>
      <button class="preset-btn" data-theme="system">system</button>
    </span>
  </div>
</div>
```

JS:

```javascript
    document.querySelectorAll('[data-theme]').forEach(b => {
      b.onclick = () => {
        const t = b.dataset.theme;
        const eff = t === 'system' ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') : t;
        document.documentElement.setAttribute('data-theme', eff);
        localStorage.setItem('kk_theme', t);
      };
    });
    // restore saved preference on every page (move to global init)
    const saved = localStorage.getItem('kk_theme');
    if (saved) {
      const eff = saved === 'system' ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') : saved;
      document.documentElement.setAttribute('data-theme', eff);
    }
```

- [ ] **Step 3: Commit**

```bash
git add src/keys_keeper/static/app.css src/keys_keeper/templates/settings.html src/keys_keeper/static/app.js
git commit -m "feat: light theme + persistence"
```

### Task 8.2: `keys doctor` exhaustive checks

**Files:**
- Modify: `src/keys_keeper/cli.py` (extend `cmd_doctor`)
- Modify: `tests/test_cli_doctor.py`

- [ ] **Step 1: Append checks to `cmd_doctor`**

After the existing checks, add:

```python
    # data.json validity
    try:
        store = MetadataStore(paths)
        entries = store.list()
        print(f"data.json:    ✓ {len(entries)} entries")
    except Exception as ex:
        print(f"data.json:    ✗ ERROR — {ex}")

    # ref integrity
    from keys_keeper.refs import detect_cycles, RefCycleError
    try:
        detect_cycles(entries)
        print("refs:         ✓ no cycles")
    except RefCycleError as ex:
        print(f"refs:         ✗ {ex}")

    # orphan refs (target missing)
    by_name = {e.name for e in entries}
    orphans = []
    for e in entries:
        for r in e.refs:
            if r.get("name") not in by_name:
                orphans.append((e.name, r.get("name")))
    if orphans:
        print(f"refs:         ⚠ {len(orphans)} orphan ref(s):")
        for src, tgt in orphans:
            print(f"   {src} → {tgt} (missing)")
    else:
        print("refs:         ✓ all targets exist")

    # keychain orphans (account exists but no metadata) and missing (metadata but no keychain)
    try:
        kc_ids = set(_backend().list_ids())
    except Exception:
        kc_ids = None
    if kc_ids is not None:
        meta_ids = {e.id for e in entries}
        # passphrase variants
        meta_ids |= {e.id + ":passphrase" for e in entries if e.type.value == "ssh_key"}
        kc_orphans = kc_ids - meta_ids
        meta_orphans = {e.id for e in entries if e.type.value in ("api_key", "ssh_key", "note") and e.id not in kc_ids}
        if kc_orphans:
            print(f"keychain:     ⚠ {len(kc_orphans)} keychain entry/entries without metadata")
        if meta_orphans:
            print(f"keychain:     ⚠ {len(meta_orphans)} metadata entry/entries missing keychain blobs")
        if not kc_orphans and not meta_orphans:
            print("keychain:     ✓ in sync with metadata")
```

- [ ] **Step 2: Test**

Append to `tests/test_cli_doctor.py`:

```python
def test_doctor_reports_data_count(cli_env, capsys, monkeypatch):
    from io import StringIO
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    cli.main(["add", "doc-test", "--type", "api_key", "--stdin"])
    capsys.readouterr()
    cli.main(["doctor"])
    out = capsys.readouterr().out
    assert "1 entries" in out or "1 entry" in out
```

- [ ] **Step 3: Commit**

```bash
pytest tests/test_cli_doctor.py -v
git add src/keys_keeper/cli.py tests/test_cli_doctor.py
git commit -m "feat: doctor reports refs / orphans / keychain sync"
```

### Task 8.3: End-to-end smoke through Claude Code

**Files:**
- Create: `tests/test_e2e_admin.py` (skipped on CI by default; manual)

- [ ] **Step 1: Write a manual E2E checklist as a doc**

Create `docs/superpowers/plans/manual-e2e-checklist.md`:

```markdown
# Manual end-to-end smoke checklist

Run before each release. Each step should produce no plaintext in any visible terminal/transcript output.

## Setup

- [ ] `pipx install --force .`
- [ ] `keys doctor` — clean
- [ ] `./scripts/install_skill.sh --force`

## CLI flow

- [ ] `pbcopy <<<"sk-test"` then `keys add e2e-test --type api_key --from-clipboard`
- [ ] `keys list` shows `e2e-test`
- [ ] `keys info e2e-test` shows metadata, no value
- [ ] `keys reveal e2e-test` errors (env unset)
- [ ] `KEYS_KEEPER_ALLOW_REVEAL=1 keys reveal e2e-test` prints value
- [ ] `echo "OTHER=foo" > /tmp/.env-test; keys inject e2e-test --file /tmp/.env-test --as MY_KEY` — file has both lines
- [ ] `cat /tmp/.env-test` — visible to user only
- [ ] `keys copy e2e-test`; `pbpaste` shows value; wait 30s; `pbpaste` is empty
- [ ] `keys export /tmp/backup.kk` (password "test"); `keys rm e2e-test`; `keys import /tmp/backup.kk` — restored

## Web admin flow

- [ ] `keys serve` opens browser
- [ ] Dashboard shows entries with unified-table layout
- [ ] Search "e2e" filters
- [ ] Click entry → detail page renders
- [ ] Cmd+K palette opens, navigates
- [ ] /paste → paste 3 entries → preview shows them → save all → dashboard updated
- [ ] /audit shows recent events
- [ ] /settings → shutdown button stops the server
- [ ] DOM never contains the secret value at any point — verify in DevTools

## Claude Code flow

- [ ] In Claude Code: "сохрани ключ из буфера как claude-test" — runs `keys add claude-test --from-clipboard`
- [ ] "вставь claude-test в /tmp/.env-test как CLAUDE_KEY" — runs `keys inject ...` (no plaintext in transcript)
- [ ] "покажи мои ключи" — runs `keys list`
- [ ] "что в audit за последние 24 часа?" — runs `keys audit --since 24h`
- [ ] Verify the transcript: search for `sk-` or any obvious value pattern → must be ZERO matches
```

- [ ] **Step 2: Run the checklist manually, fix anything that breaks**

(This is human-driven; expect 1-2 iterations of bug-fix commits.)

- [ ] **Step 3: Commit + tag**

```bash
git add docs/superpowers/plans/manual-e2e-checklist.md
git commit -m "chore: manual E2E checklist"
git tag v0.1.0
```

---

## Open questions (deferred)

These were not explicitly answered in the spec; sensible defaults are used in the plan above. Surface them to the user only if they become blockers during implementation.

- **CLI binary distribution** — pipx install vs. single-file copy. Plan picks pipx for clean dependency mgmt; if user wants `~/bin/keys` as a single file, we can ship a `pip install --target` snapshot in a post-v0.1 task.
- **Browser auto-open from `keys serve`** — uses `subprocess.Popen(["open", URL])` (macOS). If user runs in headless SSH, they need `--no-open`.
- **Token regeneration on each `keys serve`** — yes, every boot generates a new token. No persistence between server restarts.
- **`pbcopy` clear via subprocess shell** — works on user's interactive shell; in pure pipx-installed CLI runs the `sh -c "sleep 30 ..."` is started detached. If `pipx`'s wrapper closes stdin oddly, the daemonized clear may not run. Mitigation: also do the in-process `threading.Timer` form (already in `api.py`'s _copy).

## Self-review

**Spec coverage:**

- ✅ Design doc §0 decisions table — all 10 locked decisions addressed across phases.
- ✅ Design doc §1 architecture — KeychainBackend (1.3), MetadataStore (1.4), AuditLog (1.5), CLI (1.6-1.8 + 2.2 + 6.1), Web admin (3.1-5.2), Skill (7.1).
- ✅ Design doc §2 data model — Entry dataclass (1.2), refs (2.1), schema_version migration (1.4).
- ✅ Design doc §3 CLI surface — every subcommand has a task (`add` 1.6, `list/info` 1.6, `reveal/copy` 1.7, `inject/resolve/rm/edit/doctor` 1.8, `ssh` 2.2, `serve` 3.3, `export/import` 6.1, `audit` 5.1 via API though CLI counterpart not yet — flagged below, see add-on).
- ✅ Design doc §4 skill markdown — verbatim in 7.1.
- ✅ Design doc §5 web admin — full coverage (3.1 server, 3.2 API, 3.3 templates, 3.4 dashboard, 4.1-4.5 CRUD, 5.1-5.2 audit/settings).
- ✅ Design doc §6 security model — token stripped (3.1, 3.3), no-cache headers (3.1), copy hash-and-clear (1.7 + 3.2), reveal env-gating (1.7), flock (1.4).
- ✅ Design doc §7 install — Task 7.1 + 7.2 + READMEs.
- ✅ UX spec locked variants — unified-table (3.4), comfortable rows (3.4), split-horizontal bulk (4.4), bar charts (5.1), rust accent (3.3 via CSS port), system theme + dark default (8.1).

**Gap found:** the design doc lists `keys audit` as a CLI subcommand. The plan only implements `/api/audit` for the web admin. Adding a CLI version is a small addition — splice it into Task 1.8 (or Task 5.1) before shipping v0.1.

**Placeholder scan:** no "TBD" / "TODO" / "fill in details" remain. All steps include exact code or exact commands.

**Type consistency:**
- `Entry.from_dict` signature consistent across uses ✓
- `MetadataStore.add / update / replace_by_name / delete_by_name / get_by_name / get_by_id / list` consistent across CLI + API ✓
- `KeychainBackend.get / set / delete / list_ids` consistent ✓
- `AuditLog.record(*, op, name, id_, file_target=None, success=True, error=None)` consistent across CLI + API call sites ✓
- `_backend()` factory used identically in cli.py and api.py ✓

**Patch — add `keys audit` CLI command (insert into Task 1.8 step 5):**

```python
def cmd_audit(args: argparse.Namespace) -> int:
    paths = Paths()
    audit = AuditLog(paths)
    from datetime import datetime, timezone, timedelta
    since = None
    if args.since:
        amount = int(args.since[:-1])
        unit = args.since[-1]
        delta = {"h": "hours", "d": "days"}[unit]
        since = datetime.now(timezone.utc) - timedelta(**{delta: amount})
    events = list(audit.search(op=args.op, name=args.name, since=since, limit=args.limit))
    if args.tail:
        events = events[-args.limit:]
    for ev in events:
        print(f"{ev['ts']}  {ev['op']:8s}  {ev['name']:24s}  {ev.get('file_target') or '-'}")
    return 0
```

```python
    # audit CLI
    au = sub.add_parser("audit", help="show audit log")
    au.add_argument("--name")
    au.add_argument("--op")
    au.add_argument("--since", help="e.g. 24h, 7d")
    au.add_argument("--limit", type=int, default=100)
    au.add_argument("--tail", action="store_true")
    au.set_defaults(func=cmd_audit)
```

Plan is now spec-complete.
