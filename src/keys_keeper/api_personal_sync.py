"""Local authenticated UI actions. Connection codes are never GET metadata."""
from __future__ import annotations

from keys_keeper.personal_sync import PersonalSync
from keys_keeper.pairing import PairingError
from keys_keeper.project_runtime import RuntimeErrorSafe
from keys_keeper.request_json import request_object


_POST_FIELDS = {
    "setup": {"endpoint": str, "admin_token_entry": str, "name": str, "all_keys": bool},
    "join": {"code": str, "name": str},
    "approve": {"pair_id": str, "fingerprint": str},
    "auto": {"enabled": bool},
    "revoke": {"device_id": str},
}


def handle_personal_api(handler, *, paths, method, parsed, body, runtime=None, server_selector=None):
    if server_selector is not None or parsed.query:
        handler._send_json(403, {"error": "Open the default local Settings to manage your computers"})
        return
    action = parsed.path.removeprefix("/api/personal-sync/")
    allowed = {"GET": {"status", "options", "pending"},
               "POST": {"setup", "invite", "join", "approve", "sync", "poll", "cancel", "auto", "revoke"}}
    if action not in allowed.get(method, ()):
        handler._send_json(404, {"error": "Unknown personal sync operation"})
        return
    try:
        manager = PersonalSync(paths, runtime)
        if method == "GET" and action == "status":
            result = manager.status()
        elif method == "GET" and action == "options":
            result = manager.options()
        elif method == "GET" and action == "pending":
            result = {"requests": manager.pending()}
        else:
            fields = _POST_FIELDS.get(action, {})
            data = request_object(body, fields, required=set(fields))
            if action == "setup":
                result = manager.setup(**data)
                result.update(manager.set_auto(True))
            elif action == "invite":
                result = manager.invite()
            elif action == "join":
                result = manager.join(**data)
                result.update(manager.set_auto(True))
            elif action == "approve":
                result = manager.approve(**data)
            elif action == "sync":
                result = manager.sync()
            elif action == "poll":
                result = manager.poll_worker()
            elif action == "cancel":
                result = manager.cancel_pending()
            elif action == "auto":
                result = manager.set_auto(data["enabled"])
            elif action == "revoke":
                result = manager.revoke(data["device_id"])
            else:
                raise ValueError()
        handler._send_json(200, result)
    except (RuntimeErrorSafe, PairingError) as ex:
        if getattr(ex, "committed", None) is True:
            raise
        handler._send_json(400, {"error": str(ex)})
    except (ValueError, TypeError, KeyError) as ex:
        if getattr(ex, "committed", None) is True:
            raise
        handler._send_json(400, {"error": "Invalid personal sync request"})
    except Exception as ex:
        if getattr(ex, "committed", None) is True:
            raise
        handler._send_json(503, {"error": "Could not complete this operation. Check the VPS connection and retry."})
