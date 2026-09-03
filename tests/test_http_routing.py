"""Characterization tests for the admin HTTP dispatch contract."""

from keys_keeper import api
from keys_keeper.paths import Paths


class _Handler:
    def __init__(self) -> None:
        self.responses = []

    def _send_json(self, status, body) -> None:
        self.responses.append((status, body))


def test_exact_api_route_forwards_query_without_body(monkeypatch):
    calls = []
    monkeypatch.setattr(
        api,
        "_entries",
        lambda handler, paths, query: calls.append((handler, paths, query)),
    )
    handler = _Handler()
    paths = Paths()

    api.handle_api(
        handler,
        paths=paths,
        method="GET",
        path="/api/entries?tag=ops%20team",
        body=None,
    )

    assert calls == [(handler, paths, "tag=ops%20team")]
    assert handler.responses == []


def test_dynamic_entry_routes_keep_decoding_query_and_body(monkeypatch):
    calls = []
    monkeypatch.setattr(
        api,
        "_entry_detail",
        lambda handler, paths, entry_id: calls.append(("GET", entry_id, None)),
    )
    monkeypatch.setattr(
        api,
        "_patch_entry",
        lambda handler, paths, entry_id, body: calls.append(("PATCH", entry_id, body)),
    )
    monkeypatch.setattr(
        api,
        "_delete_entry",
        lambda handler, paths, entry_id, query: calls.append(
            ("DELETE", entry_id, query)
        ),
    )
    monkeypatch.setattr(
        api,
        "_replace_secret",
        lambda handler, paths, entry_id, body: calls.append(
            ("replace-secret", entry_id, body)
        ),
    )
    handler = _Handler()
    paths = Paths()

    api.handle_api(
        handler,
        paths=paths,
        method="GET",
        path="/api/entries/team%20key",
        body=None,
    )
    api.handle_api(
        handler,
        paths=paths,
        method="PATCH",
        path="/api/entries/team%20key",
        body=b"patch",
    )
    api.handle_api(
        handler,
        paths=paths,
        method="DELETE",
        path="/api/entries/team%20key?cascade=yes",
        body=None,
    )
    api.handle_api(
        handler,
        paths=paths,
        method="POST",
        path="/api/entries/team%20key/replace-secret",
        body=b"secret",
    )

    assert calls == [
        ("GET", "team key", None),
        ("PATCH", "team key", b"patch"),
        ("DELETE", "team key", "cascade=yes"),
        ("replace-secret", "team key", b"secret"),
    ]
    assert handler.responses == []


def test_unknown_path_or_wrong_method_is_identical_404():
    for method, path in (
        ("PUT", "/api/entries"),
        ("GET", "/api/missing"),
        ("POST", "/api/entries/name"),
    ):
        handler = _Handler()

        api.handle_api(handler, paths=Paths(), method=method, path=path, body=None)

        assert handler.responses == [(404, {"error": "not found"})]
