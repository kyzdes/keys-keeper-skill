from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADMIN_CSS = ROOT / "src" / "keys_keeper" / "static" / "app.css"
WEB_CSS = ROOT / "src" / "keys_keeper" / "webvault" / "static" / "app.css"
TOKEN_SOURCE = ROOT / "scripts" / "ui_theme_tokens.json"
TOKEN_GENERATOR = ROOT / "scripts" / "generate_ui_tokens.py"
LANDING_HTML = ROOT / "docs" / "landing" / "index.html"


def _tokens(css: str, selector: str) -> dict[str, str]:
    match = re.search(re.escape(selector) + r"\s*\{(.*?)\n\}", css, re.DOTALL)
    assert match, f"missing token block {selector}"
    return dict(re.findall(r"--([\w-]+):\s*([^;]+);", match.group(1)))


def _luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_admin_and_webvault_share_semantic_theme_tokens():
    source = json.loads(TOKEN_SOURCE.read_text(encoding="utf-8"))
    admin = ADMIN_CSS.read_text(encoding="utf-8")
    web = WEB_CSS.read_text(encoding="utf-8")
    for theme in source["themes"].values():
        selector = theme["selector"]
        admin_tokens = _tokens(admin, selector)
        web_tokens = _tokens(web, selector)
        expected = set(theme["tokens"])
        assert expected <= admin_tokens.keys()
        assert {key: admin_tokens[key] for key in expected} == {
            key: web_tokens[key] for key in expected
        }


def test_dark_theme_uses_the_landing_visual_palette():
    source = json.loads(TOKEN_SOURCE.read_text(encoding="utf-8"))
    landing = _tokens(LANDING_HTML.read_text(encoding="utf-8"), ":root")
    panel = source["themes"]["evening"]["tokens"]
    shared_roles = {
        "bg",
        "bg-elevated",
        "surface",
        "surface-2",
        "surface-hover",
        "text",
        "text-2",
        "accent",
        "accent-soft",
        "accent-line",
        "success",
        "success-soft",
        "danger",
        "danger-soft",
        "warning",
        "info",
        "type-api",
        "type-ssh",
        "type-server",
        "type-domain",
        "type-note",
        "shadow-md",
        "shadow-lg",
    }
    assert {role: panel[role] for role in shared_roles} == {
        role: landing[role] for role in shared_roles
    }


def test_ui_token_css_is_generated_from_canonical_source():
    result = subprocess.run(
        [sys.executable, str(TOKEN_GENERATOR), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_ui_uses_one_ui_stack_and_no_external_font_dependency():
    targets = [
        ROOT / "src" / "keys_keeper" / "templates" / "base.html",
        ADMIN_CSS,
        ROOT / "src" / "keys_keeper" / "webvault" / "static" / "index.html",
        WEB_CSS,
        ROOT / "src" / "keys_keeper" / "webvault" / "static" / "vault.css",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in targets)
    assert "fonts.googleapis.com" not in combined
    assert "fonts.gstatic.com" not in combined
    assert "JetBrains Mono" not in combined
    assert "'Inter'" not in combined
    assert "var(--font-ui)" in combined
    assert "var(--font-mono)" in combined


def test_control_boundaries_have_non_text_contrast_in_both_themes():
    css = ADMIN_CSS.read_text(encoding="utf-8")
    for selector in (":root", ':root[data-theme="light"]'):
        tokens = _tokens(css, selector)
        assert _contrast(tokens["border"], tokens["bg"]) >= 3
        assert _contrast(tokens["border"], tokens["surface"]) >= 3
        assert _contrast(tokens["border"], tokens["surface-2"]) >= 3


def test_quiet_text_and_primary_actions_pass_in_both_themes():
    css = ADMIN_CSS.read_text(encoding="utf-8")
    for selector in (":root", ':root[data-theme="light"]'):
        tokens = _tokens(css, selector)
        for surface in ("bg", "surface", "surface-2"):
            assert _contrast(tokens["text-4"], tokens[surface]) >= 4.5
        assert _contrast(tokens["accent"], tokens["bg"]) >= 4.5
        assert _contrast(tokens["accent"], tokens["accent-ink"]) >= 4.5


def test_type_icons_use_readable_ink_and_theme_matched_backgrounds():
    css = ADMIN_CSS.read_text(encoding="utf-8")
    roles = ("type-api", "type-ssh", "type-server", "type-domain", "type-note")
    for selector in (":root", ':root[data-theme="light"]'):
        tokens = _tokens(css, selector)
        for role in roles:
            background = tokens[f"{role}-icon-bg"]
            ink = tokens[f"{role}-icon-ink"]
            assert _contrast(ink, background) >= 4.5
            assert _contrast(background, tokens["surface"]) >= 1.2


def test_browser_theme_color_tracks_theme_canvas_tokens():
    source = json.loads(TOKEN_SOURCE.read_text(encoding="utf-8"))
    dark = source["themes"]["evening"]["tokens"]["bg"]
    light = source["themes"]["day"]["tokens"]["bg"]
    targets = [
        ROOT / "src" / "keys_keeper" / "static" / "app.js",
        ROOT / "src" / "keys_keeper" / "webvault" / "static" / "theme.js",
        ROOT / "src" / "keys_keeper" / "webvault" / "static" / "vault.mjs",
    ]
    for path in targets:
        content = path.read_text(encoding="utf-8")
        assert dark in content
        assert light in content


def test_webvault_bundle_has_no_inherited_admin_or_env_panel_styles():
    web = WEB_CSS.read_text(encoding="utf-8")
    vault = (
        ROOT / "src" / "keys_keeper" / "webvault" / "static" / "vault.css"
    ).read_text(encoding="utf-8")
    assert ".env-panel" not in web + vault
    assert ".app-topbar" not in web + vault
    assert '[data-accent="teal"]' not in web + vault


def test_bulk_preview_never_reads_or_infers_secret_value():
    js = (ROOT / "src" / "keys_keeper" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    assert "r.value.includes" not in js
    assert "r.value.split" not in js
    assert "r.value.length" not in js
    assert "r.has_value ? 'value present' : 'no value'" in js


def test_webvault_theme_and_keyboard_contracts_are_present():
    js = (ROOT / "src" / "keys_keeper" / "webvault" / "static" / "vault.mjs").read_text(
        encoding="utf-8"
    )
    assert "function themeControl()" in js
    assert 'role: "button", tabindex: "0"' in js
    assert 'event.key === "Enter" || event.key === " "' in js
    assert 'role: "alert", "aria-live": "polite"' in js


def test_webvault_theme_bootstrap_precedes_css_and_is_sri_protected():
    static = ROOT / "src" / "keys_keeper" / "webvault" / "static"
    index = (static / "index.html").read_text(encoding="utf-8")
    bootstrap = (static / "theme.js").read_text(encoding="utf-8")
    assert index.index("/static/theme.js") < index.index("/static/app.css")
    assert 'integrity="__SRI_THEME__"' in index
    assert "keys-keeper-theme" in bootstrap
    assert "prefers-color-scheme: light" in bootstrap


def test_command_palette_fits_narrow_viewports():
    css = ADMIN_CSS.read_text(encoding="utf-8")
    assert "padding: 18vh 12px 12px" in css
    assert "width: min(580px, 100%)" in css
