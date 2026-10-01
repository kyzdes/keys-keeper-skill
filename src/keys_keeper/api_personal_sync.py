"""Local authenticated UI actions. Connection codes are never GET metadata."""
from __future__ import annotations

import json

from keys_keeper.personal_sync import PersonalSync
from keys_keeper.pairing import PairingError
from keys_keeper.project_runtime import RuntimeErrorSafe


def handle_personal_api(handler, *, paths, method, parsed, body, runtime=None, server_selector=None):
    if server_selector is not None or parsed.query:
        handler._send_json(403, {"error": "Open the default local Settings to manage your computers"})
        return
    manager = PersonalSync(paths, runtime)
    action = parsed.path.removeprefix("/api/personal-sync/")
    try:
        if method == "GET" and action == "status":
            result = manager.status()
        elif method == "GET" and action == "options":
            result = manager.options()
        elif method == "GET" and action == "pending":
            result = {"requests": manager.pending()}
        elif method == "POST":
            data = json.loads(body or b"{}")
            if not isinstance(data, dict):
                raise ValueError()
            if action == "setup" and set(data) == {"endpoint", "admin_token_entry", "name", "all_keys"}:
                result = manager.setup(**data)
                result.update(manager.set_auto(True))
            elif action == "invite" and not data:
                result = manager.invite()
            elif action == "join" and set(data) == {"code", "name"}:
                result = manager.join(**data)
                result.update(manager.set_auto(True))
            elif action == "approve" and set(data) == {"pair_id", "fingerprint"}:
                result = manager.approve(**data)
            elif action == "sync" and not data:
                result = manager.sync()
            elif action == "poll" and not data:
                result = manager.poll_worker()
            elif action == "cancel" and not data:
                result = manager.cancel_pending()
            elif action == "auto" and set(data) == {"enabled"}:
                result = manager.set_auto(data["enabled"])
            elif action == "revoke" and set(data) == {"device_id"}:
                result = manager.revoke(data["device_id"])
            else:
                raise ValueError()
        else:
            handler._send_json(404, {"error": "Unknown personal sync operation"})
            return
        handler._send_json(200, result)
    except (RuntimeErrorSafe, PairingError) as ex:
        handler._send_json(400, {"error": str(ex)})
    except (ValueError, TypeError, KeyError):
        handler._send_json(400, {"error": "Invalid personal sync request"})
    except Exception:
        handler._send_json(503, {"error": "Could not complete this operation. Check the VPS connection and retry."})
