"""Personal API routing/errors without a vault, backend, relay, or sync."""
import copy
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from keys_keeper import api_personal_sync as api
from keys_keeper.pairing import PairingError
from keys_keeper.project_runtime import RuntimeErrorSafe


class Handler:
    def __init__(self):
        self.responses = []

    def _send_json(self, status, payload):
        self.responses.append((status, copy.deepcopy(payload)))


@pytest.fixture
def boundary(monkeypatch):
    calls = []
    failures = {}
    paths, runtime = object(), object()

    class FakeManager:
        def __getattr__(self, method):
            def action(*args, **kwargs):
                calls.append((method, args, kwargs))
                if method in failures:
                    raise failures[method]
                if method == "pending":
                    return [{"pair_id": "synthetic-pair", "fingerprint": "synthetic-fingerprint"}]
                if method == "set_auto":
                    return {"auto": args[0]}
                return {"operation": method}
            return action

    manager = FakeManager()

    def construct(actual_paths, actual_runtime):
        calls.append(("construct", (actual_paths, actual_runtime), {}))
        if "construct" in failures:
            raise failures["construct"]
        return manager

    monkeypatch.setattr(api, "PersonalSync", construct)

    def invoke(action, *, method="POST", data=None, raw=None, query="", selector=None):
        handler = Handler()
        body = raw if raw is not None else json.dumps({} if data is None else data).encode()
        api.handle_personal_api(handler, paths=paths, runtime=runtime, method=method,
                                parsed=urlsplit("/api/personal-sync/" + action + query),
                                body=body, server_selector=selector)
        assert len(handler.responses) == 1
        return handler.responses[0]

    return SimpleNamespace(calls=calls, failures=failures, invoke=invoke,
                           paths=paths, runtime=runtime)


@pytest.mark.parametrize("action,manager_method", [
    ("status", "status"), ("options", "options"), ("pending", "pending"),
])
def test_get_metadata_routes_invoke_only_expected_manager_action(boundary, action, manager_method):
    status, body = boundary.invoke(action, method="GET")
    assert status == 200
    assert body == ({"requests": [{"pair_id": "synthetic-pair", "fingerprint": "synthetic-fingerprint"}]}
                    if action == "pending" else {"operation": manager_method})
    assert boundary.calls == [("construct", (boundary.paths, boundary.runtime), {}),
                              (manager_method, (), {})]


POSTS = [
    ("setup", {"endpoint": "https://synthetic.invalid", "admin_token_entry": "synthetic-entry",
               "name": "Synthetic computer", "all_keys": False}, "setup", (), True),
    ("invite", {}, "invite", (), False),
    ("join", {"code": "synthetic-code", "name": "Synthetic computer"}, "join", (), True),
    ("approve", {"pair_id": "synthetic-pair", "fingerprint": "synthetic-fingerprint"}, "approve", (), False),
    ("sync", {}, "sync", (), False),
    ("poll", {}, "poll_worker", (), False),
    ("cancel", {}, "cancel_pending", (), False),
    ("auto", {"enabled": False}, "set_auto", (False,), False),
    ("revoke", {"device_id": "synthetic-device"}, "revoke", ("synthetic-device",), False),
]


@pytest.mark.parametrize("action,data,manager_method,args,auto", POSTS)
def test_post_exact_schema_routes_and_setup_join_enable_auto_after_success(
        boundary, action, data, manager_method, args, auto):
    status, body = boundary.invoke(action, data=data)
    assert status == 200
    expected = {"auto": False} if action == "auto" else {"operation": manager_method}
    if auto:
        expected["auto"] = True
    assert body == expected
    kwargs = {} if action in {"auto", "revoke"} else data
    expected_calls = [("construct", (boundary.paths, boundary.runtime), {}),
                      (manager_method, args, kwargs)]
    if auto:
        expected_calls.append(("set_auto", (True,), {}))
    assert boundary.calls == expected_calls


@pytest.mark.parametrize("action,data,manager_method,args,auto", POSTS)
def test_extra_keys_rejected_without_any_manager_action(boundary, action, data, manager_method, args, auto):
    status, body = boundary.invoke(action, data={**data, "unexpected": "synthetic"})
    assert (status, body) == (400, {"error": "Invalid personal sync request"})
    assert boundary.calls == [("construct", (boundary.paths, boundary.runtime), {})]


@pytest.mark.parametrize("action,data,manager_method,args,auto", [post for post in POSTS if post[1]])
def test_missing_schema_keys_rejected_without_mutation(boundary, action, data, manager_method, args, auto):
    status, body = boundary.invoke(action, data={key: value for index, (key, value) in enumerate(data.items()) if index})
    assert (status, body) == (400, {"error": "Invalid personal sync request"})
    assert len(boundary.calls) == 1


@pytest.mark.parametrize("raw", [b"{", b"[]", b"null", b'"synthetic"', b"1", b"true", b"\xff"])
def test_malformed_or_nonobject_json_does_not_call_manager_action(boundary, raw):
    assert boundary.invoke("sync", raw=raw) == (400, {"error": "Invalid personal sync request"})
    assert len(boundary.calls) == 1


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("restriction", ["selector", "query"])
def test_scope_selector_or_any_query_rejects_before_manager_construction(boundary, method, restriction):
    options = {"selector": "synthetic-profile"} if restriction == "selector" else {"query": "?ignored="}
    status, body = boundary.invoke("status", method=method, **options)
    assert status == 403
    assert body == {"error": "Open the default local Settings to manage your computers"}
    assert boundary.calls == []


@pytest.mark.parametrize("method,action", [("GET", "missing"), ("POST", "missing"),
                                           ("DELETE", "status"), ("GET", "sync")])
def test_unknown_or_unsupported_route_returns_404_without_manager_action(boundary, method, action):
    assert boundary.invoke(action, method=method) == (404, {"error": "Unknown personal sync operation"})
    assert boundary.calls == []


@pytest.mark.parametrize("raw", [b'{"enabled":true,"enabled":false}',
                                b'{"enabled":{"nested":true,"nested":false}}'])
def test_duplicate_json_keys_never_reach_auto_action(boundary, raw):
    assert boundary.invoke("auto", raw=raw) == (400, {"error": "Invalid personal sync request"})
    assert len(boundary.calls) == 1


def test_unknown_post_rejected_before_constructor_or_json_parse(boundary):
    boundary.failures["construct"] = OSError("synthetic-private-value")
    assert boundary.invoke("missing", raw=b"{", method="POST") == (404, {"error": "Unknown personal sync operation"})
    assert boundary.calls == []


@pytest.mark.parametrize("where", ["construct", "sync"])
@pytest.mark.parametrize("error", [RuntimeErrorSafe("Synthetic safe runtime error"),
                                   PairingError("Synthetic safe pairing error")])
def test_declared_safe_errors_are_400_including_constructor(boundary, where, error):
    boundary.failures[where] = error
    assert boundary.invoke("sync") == (400, {"error": str(error)})


@pytest.mark.parametrize("error", [ValueError("private-marker"), TypeError("private-marker"), KeyError("private-marker")])
def test_invalid_action_input_is_400_with_constant_redacted_error(boundary, error):
    boundary.failures["sync"] = error
    assert boundary.invoke("sync") == (400, {"error": "Invalid personal sync request"})


@pytest.mark.parametrize("where", ["construct", "sync"])
def test_unexpected_failure_is_503_and_never_discloses_exception(boundary, where):
    boundary.failures[where] = OSError("synthetic-private-value /synthetic/private/path")
    response = boundary.invoke("sync")
    assert response == (503, {"error": "Could not complete this operation. Check the VPS connection and retry."})
    assert "synthetic-private" not in json.dumps(response)


@pytest.mark.parametrize("action", ["setup", "join"])
def test_setup_or_join_failure_does_not_enable_automatic_sync(boundary, action):
    data = next(post[1] for post in POSTS if post[0] == action)
    boundary.failures[action] = RuntimeErrorSafe("Synthetic declined enrollment")
    assert boundary.invoke(action, data=data) == (400, {"error": "Synthetic declined enrollment"})
    assert [call[0] for call in boundary.calls] == ["construct", action]
