# Keys Keeper

<!-- impeccable:product-schema 1 -->

## Platform

web

The existing local web admin also has a native macOS menu bar companion. The
companion hosts the existing admin in a WebKit window.

## Users

The owner finds and copies credentials; local coding agents use the CLI to
deliver secrets to explicit sinks. The owner wants to see today's agent usage
without opening a terminal.

## Product Purpose

Keep credentials in the existing Keys Keeper backend and make routine access
and its recorded activity easy to inspect.

## Capabilities and Constraints

- A key icon in the macOS menu bar opens a compact activity panel.
- The user confirmed that open/close means show/hide the window.
- Statistics count recorded credential operations since local midnight on this
  Mac. Unknown callers remain unknown; historical records are not relabelled.
- Statistics must not retrieve secrets or trigger Keychain authorization.
- Existing CLI, vault formats, permissions, and web workflows stay authoritative.
- The current web interface and shipped icon provide the incumbent identity.

## Evidence on Hand

`src/keys_keeper/audit.py`, `src/keys_keeper/server.py`,
`src/keys_keeper/macos_app.py`, and `scripts/ui_theme_tokens.json`.

## Product Principles

- Open, find, copy with little navigation.
- Distinguish agent attribution from unknown callers.
- Keep secret values out of activity summaries and logs.
- Closing a window is a presentation action.
