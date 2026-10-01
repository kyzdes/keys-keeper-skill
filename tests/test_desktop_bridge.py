import json
import io
import os
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import urlopen

import pytest


def test_failed_open_can_retry_with_a_new_server(monkeypatch, capsys, tmp_path):
    from keys_keeper import desktop_bridge, server
    from threading import Event

    attempts = []

    class RetryServer:
        def __init__(self, **kwargs):
            attempts.append(self)
            self._stop_event = Event()
            self._server = None
            self.bound_port = 54321
            self.token = "a" * 64

        def start(self):
            if len(attempts) == 1:
                raise OSError("synthetic bind failure")

        def heartbeat(self):
            pass

        def serve_forever(self):
            pass

        def stop(self):
            self._stop_event.set()

    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path))
    monkeypatch.setenv("KEYS_KEEPER_CALLER", "unknown")
    monkeypatch.setattr(server, "AdminServer", RetryServer)
    monkeypatch.setattr(sys, "stdin", io.StringIO(
        '{"command":"open"}\n{"command":"open"}\n{"command":"quit"}\n'))
    assert desktop_bridge.main() == 0
    responses = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert responses[0] == {"type": "error", "error": "request_failed", "command": "open"}
    assert responses[1]["type"] == "open"
    assert len(attempts) == 2
    assert attempts[-1]._stop_event.is_set()


def test_private_bridge_owns_server_auth_and_exits_on_stdin_close(tmp_path):
    env = dict(os.environ, KEYS_KEEPER_HOME=str(tmp_path / "empty-vault"))
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    process = subprocess.Popen([sys.executable, "-u", "-m", "keys_keeper.desktop_bridge"],
                               env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        process.stdin.write('{"command":"summary"}\n{"command":"open","page":"audit"}\n')
        process.stdin.flush()
        summary = json.loads(process.stdout.readline())
        opened = json.loads(process.stdout.readline())
        assert summary["summary"]["total"] == 0
        assert opened["page"] == "audit"
        url = urlsplit(opened["url"])
        assert url.hostname == "127.0.0.1"
        assert url.port != 7777
        origin = f"http://127.0.0.1:{url.port}"
        with pytest.raises(HTTPError) as exc:
            urlopen(origin + "/api/heartbeat", timeout=3)
        assert exc.value.code == 403
        # The native window bootstraps its HttpOnly cookie using this private URL.
        with urlopen(opened["url"], timeout=3) as response:
            assert response.status == 200
            assert "HttpOnly" in response.headers["Set-Cookie"]
        assert not (tmp_path / "empty-vault" / "serve-url").exists()
        process.stdin.close()
        assert process.wait(timeout=5) == 0
        assert process.stderr.read() == ""
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
