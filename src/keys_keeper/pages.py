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
