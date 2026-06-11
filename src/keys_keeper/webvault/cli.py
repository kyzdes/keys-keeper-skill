"""`keys webvault serve` — run the zero-knowledge web vault proxy."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from keys_keeper.paths import Paths


def cmd_webvault_serve(args: argparse.Namespace) -> int:
    from keys_keeper.webvault.server import WebVaultServer
    data_dir = Path(args.data_dir) if args.data_dir else (Paths().root / "webvault")
    srv = WebVaultServer(
        data_dir=data_dir, host=args.host, port=args.port,
        multi_tenant=args.multi_tenant or bool(os.environ.get("WEBVAULT_MULTI_TENANT")),
        register_token=(args.register_token or os.environ.get("WEBVAULT_REGISTER_TOKEN")),
        allow_open_registration=(args.allow_open_registration
                                 or bool(os.environ.get("WEBVAULT_ALLOW_OPEN_REGISTRATION"))),
        trust_forwarded=(args.behind_proxy
                         or bool(os.environ.get("WEBVAULT_BEHIND_PROXY"))),
        certfile=(args.certfile or os.environ.get("WEBVAULT_CERTFILE")),
        keyfile=(args.keyfile or os.environ.get("WEBVAULT_KEYFILE")),
    )
    srv.serve_forever()
    return 0


def register_webvault(sub) -> None:
    p = sub.add_parser("webvault", help="run the zero-knowledge web vault server")
    ps = p.add_subparsers(dest="webvault_command", required=True)
    s = ps.add_parser("serve", help="serve the web vault (browser decrypts; server never sees secrets)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8333)
    s.add_argument("--data-dir", default=None, help="account/session store dir")
    s.add_argument("--multi-tenant", action="store_true", help="namespace each account under tenants/<uid>/")
    s.add_argument("--register-token", default=None, help="gate /auth/register with this token")
    s.add_argument("--allow-open-registration", action="store_true",
                   help="allow token-less single-tenant sign-up (fail-OPEN; only safe "
                        "on a trusted/local network — registration is closed by default)")
    s.add_argument("--behind-proxy", action="store_true",
                   help="trust X-Forwarded-Proto from an upstream reverse proxy (sets "
                        "Secure cookies when it reports https). Only enable when a "
                        "trusted proxy actually terminates TLS in front of this server.")
    s.add_argument("--certfile", default=None, help="TLS cert (enables HTTPS + Secure cookies)")
    s.add_argument("--keyfile", default=None)
    s.set_defaults(func=cmd_webvault_serve)
