"""Bounded, expiring ciphertext mailboxes for personal device enrollment."""
from __future__ import annotations

import hashlib
import re
import secrets

from keys_keeper.pairing import MAX_PACKET
from keys_keeper.project_server import _error, _fields, _uuid


class PairingRelay:
    pattern = re.compile(r"/v2/scopes/([0-9a-f-]+)/pairings(?:/([0-9a-f-]+))?(?:/(request|response))?")

    def __init__(self, relay):
        self.relay, self.app = relay, relay.app
        with self.app._transaction(immediate=True) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS kk3_pairings (
                id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, token_hash TEXT NOT NULL,
                expires INTEGER NOT NULL, invitation TEXT NOT NULL,
                request TEXT, response TEXT
            )""")

    def matches(self, path):
        return self.pattern.fullmatch(path)

    def _auth(self, connection, method, path, headers):
        match = self.matches(path)
        if match is None:
            _error(404, "not_found")
        scope, pair_id, slot = match.groups()
        _uuid(scope)
        if pair_id is None:
            if method != "POST" or slot:
                _error(404, "not_found")
            self.relay._auth(connection, scope, headers, "publish")
            return scope, None, None
        _uuid(pair_id)
        row = connection.execute("SELECT * FROM kk3_pairings WHERE id=? AND scope_id=?", (pair_id, scope)).fetchone()
        if row is None:
            _error(404, "pairing_not_found")
        if headers.get("X-Device-ID"):
            self.relay._auth(connection, scope, headers, "publish")
            if slot == "request":
                _error(403, "pairing_authorization_failed")
        else:
            raw = headers.get("Authorization", "")
            digest = hashlib.sha256(raw[7:].encode()).hexdigest() if raw.startswith("Bearer ") else ""
            if not secrets.compare_digest(digest, row["token_hash"]) or slot == "response":
                _error(403, "pairing_authorization_failed")
        if row["expires"] <= self.app._clock():
            _error(410, "pairing_expired")
        if (method == "GET" and slot is not None) or (method == "POST" and slot is None):
            _error(404, "not_found")
        return scope, row, slot

    def preflight(self, method, path, headers):
        with self.app._transaction() as connection:
            self._auth(connection, method, path, headers)

    @staticmethod
    def _packet(value, maximum=MAX_PACKET):
        if not isinstance(value, str) or not 38 <= len(value) <= maximum or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            _error(422, "invalid_pairing_packet")
        return value

    def _budget(self, connection, scope, extra):
        usage = "length(invitation)+coalesce(length(request),0)+coalesce(length(response),0)"
        total = connection.execute(f"SELECT coalesce(sum({usage}),0) FROM kk3_pairings").fetchone()[0]
        local = connection.execute(f"SELECT coalesce(sum({usage}),0) FROM kk3_pairings WHERE scope_id=?", (scope,)).fetchone()[0]
        if total + extra > 256 * 1024 * 1024 or local + extra > 64 * 1024 * 1024:
            _error(429, "pairing_storage_limit")

    def handle(self, method, path, headers, payload):
        with self.app._transaction(immediate=True) as connection:
            scope, row, slot = self._auth(connection, method, path, headers)
            if row is None:
                _fields(payload, {"pair_id", "token_hash", "expires_at", "invitation"})
                pair_id = _uuid(payload["pair_id"])
                digest = payload["token_hash"]
                expires = payload["expires_at"]
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    _error(422, "invalid_pairing_token")
                if type(expires) is not int or not self.app._clock() < expires <= self.app._clock() + 900:
                    _error(422, "invalid_pairing_expiry")
                packet = self._packet(payload["invitation"], 1024 * 1024)
                connection.execute("DELETE FROM kk3_pairings WHERE expires<=?", (self.app._clock(),))
                previous = connection.execute("SELECT * FROM kk3_pairings WHERE id=?", (pair_id,)).fetchone()
                if previous is not None:
                    if (previous["scope_id"], previous["token_hash"], previous["expires"], previous["invitation"]) != (scope, digest, expires, packet):
                        _error(409, "pairing_conflict")
                    return 200, {"pair_id": pair_id, "expires_at": expires}
                if connection.execute("SELECT count(*) FROM kk3_pairings WHERE scope_id=?", (scope,)).fetchone()[0] >= 8 or connection.execute("SELECT count(*) FROM kk3_pairings").fetchone()[0] >= 128:
                    _error(429, "pairing_limit")
                self._budget(connection, scope, len(packet))
                connection.execute("INSERT INTO kk3_pairings(id,scope_id,token_hash,expires,invitation) VALUES(?,?,?,?,?)", (pair_id, scope, digest, expires, packet))
                return 201, {"pair_id": pair_id, "expires_at": expires}
            if method == "GET":
                return 200, {"pair_id": row["id"], "expires_at": row["expires"],
                             "invitation": row["invitation"], "request": row["request"], "response": row["response"]}
            _fields(payload, {"packet"})
            packet = self._packet(payload["packet"], 1024 * 1024 if slot == "request" else MAX_PACKET)
            if row[slot] is not None:
                if row[slot] != packet:
                    _error(409, "pairing_already_claimed")
                return 200, {"ok": True}
            if slot == "response" and row["request"] is None:
                _error(409, "pairing_request_required")
            self._budget(connection, scope, len(packet))
            # slot is one of two constants parsed by the route expression.
            connection.execute(f"UPDATE kk3_pairings SET {slot}=? WHERE id=?", (packet, row["id"]))
            return 201, {"ok": True}
