"""Process entrypoint for the zero-knowledge Keys Keeper VPS relay."""
from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from keys_keeper.sync_server import SyncServerApp, create_http_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keys-keeper-syncd")
    parser.add_argument(
        "--database",
        default="/var/lib/keys-keeper-syncd/syncd.sqlite3",
        help="SQLite database path (default: /var/lib/keys-keeper-syncd/syncd.sqlite3)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="allow a public bind; TLS must then be provided by a trusted reverse proxy",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0 <= args.port <= 65535:
        sys.stderr.write("error: --port must be between 0 and 65535\n")
        return 2
    token = os.environ.get("KEYS_KEEPER_SYNC_ADMIN_TOKEN")
    if not token:
        sys.stderr.write("error: KEYS_KEEPER_SYNC_ADMIN_TOKEN is required\n")
        return 2
    database = Path(args.database).expanduser()
    try:
        app = SyncServerApp(database, token)
        server = create_http_server(
            app,
            args.host,
            args.port,
            allow_non_loopback=args.allow_non_loopback,
        )
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"error: cannot start syncd: {exc}\n")
        return 1

    def stop(_signum, _frame) -> None:
        # shutdown() cannot safely be called from the serve_forever thread.
        # Raising KeyboardInterrupt reaches the common close path immediately.
        raise KeyboardInterrupt

    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, stop)
    host, port = server.server_address[:2]
    print(f"keys-keeper-syncd listening on {host}:{port}; database={database}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
