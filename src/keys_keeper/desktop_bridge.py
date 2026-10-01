"""Private stdio bridge owned by the native macOS app.

Only open/summary/quit commands exist. The capability URL travels in a pipe to
WebKit; it is never saved to serve-url, stdout logs, or process arguments.
The app's server uses its own OS-selected port and ends when stdin closes.
"""
from __future__ import annotations

import json
import os
import sys
import threading

from keys_keeper.desktop_stats import today_summary
from keys_keeper.paths import Paths


def main() -> int:
    os.environ["KEYS_KEEPER_CALLER"] = "desktop"
    paths = Paths()
    server = None
    try:
        for line in sys.stdin:
            command = None
            try:
                request = json.loads(line)
                command = request.get("command")
                if command == "quit":
                    break
                if command == "summary":
                    if server is not None:
                        server.heartbeat()
                    response = {"type": "summary", "summary": today_summary(paths)}
                elif command == "open":
                    if server is None or server._stop_event.is_set():
                        from keys_keeper.server import AdminServer
                        candidate = AdminServer(paths=paths, port=0)
                        candidate.start()
                        server = candidate
                        threading.Thread(target=server.serve_forever, daemon=True).start()
                    server.heartbeat()
                    response = {"type": "open", "url":
                                f"http://127.0.0.1:{server.bound_port}/?t={server.token}",
                                "page": "audit" if request.get("page") == "audit" else "home"}
                else:
                    response = {"type": "error", "error": "unknown_command"}
            except Exception:
                # Backend exception text may contain sensitive context.
                response = {"type": "error", "error": "request_failed"}
            if response["type"] == "error" and command in ("open", "summary"):
                response["command"] = command
            print(json.dumps(response, separators=(",", ":")), flush=True)
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    finally:
        if server is not None:
            server.stop()
            if server._server is not None:
                server._server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
