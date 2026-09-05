"""Bounded transport for the independent project synchronization API.

All policies and ciphertexts still require end-to-end verification by callers.
The transport has no secret-decryption or implicit legacy-sync fallback.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from keys_keeper import project_protocol as protocol
from keys_keeper.sync_vps_client import VpsSyncClient, VpsValidationError, VpsProtocolError


def _id(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise VpsValidationError("invalid project identifier") from None
    if str(parsed) != value or parsed.version != 4:
        raise VpsValidationError("invalid project identifier")
    return value


class ProjectClient(VpsSyncClient):
    """Reuse HTTPS, no redirects, bounded decoding and sealed authentication."""

    def _request(self, method, path, *, payload=None, **kwargs):
        # Reject unsupported local JSON before the inherited encoder/network,
        # and keep hostile deeply nested responses inside safe typed errors.
        if payload is not None:
            try:
                payload = protocol.parse_record(payload, maximum=self.max_request_bytes)
            except protocol.ProtocolError:
                raise VpsValidationError("invalid project request") from None
        try:
            result = super()._request(method, path, payload=payload, **kwargs)
            return protocol.parse_record(result, maximum=self.max_response_bytes)
        except (protocol.ProtocolError, RecursionError, UnicodeError):
            raise VpsProtocolError("invalid project response") from None

    def create_scope(self, policy: dict) -> dict:
        return self._request(
            "POST", "/v2/scopes", payload={"policy": policy},
            include_device=False, expected_statuses=(200, 201),
        )

    def state(self, scope_id: str) -> dict:
        return self._request("GET", f"/v2/scopes/{_id(scope_id)}/state")

    def policy(self, scope_id: str, policy_hash: str) -> dict:
        return self._record(scope_id, "policies", policy_hash)

    def snapshot(self, scope_id: str, snapshot_hash: str) -> dict:
        return self._record(scope_id, "snapshots", snapshot_hash)

    def _record(self, scope_id: str, kind: str, digest: str) -> dict:
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise VpsValidationError("invalid project digest")
        return self._request("GET", f"/v2/scopes/{_id(scope_id)}/{kind}/{digest}")

    def publish(self, scope_id: str, *, operation_id: str,
                expected_head_hash: str | None, policy: dict,
                snapshot: dict, wraps: list[dict]) -> dict:
        return self._request(
            "POST", f"/v2/scopes/{_id(scope_id)}/publish",
            payload={"operation_id": _id(operation_id),
                     "expected_head_hash": expected_head_hash,
                     "policy": policy, "snapshot": snapshot, "wraps": wraps},
            expected_statuses=(200, 201),
        )

    def submit(self, scope_id: str, submission: dict) -> dict:
        return self._request(
            "POST", f"/v2/scopes/{_id(scope_id)}/submissions",
            payload={"submission": submission}, expected_statuses=(200, 201),
        )

    def pending(self, scope_id: str) -> dict:
        return self._request("GET", f"/v2/scopes/{_id(scope_id)}/submissions")

    def submission(self, scope_id: str, request_id: str) -> dict:
        return self._request(
            "GET", f"/v2/scopes/{_id(scope_id)}/submissions/{_id(request_id)}",
        )

    def acknowledge(self, scope_id: str, request_id: str, receipt: dict) -> dict:
        return self._request(
            "POST", f"/v2/scopes/{_id(scope_id)}/submissions/{_id(request_id)}/receipt",
            payload={"receipt": receipt}, expected_statuses=(200, 201),
        )

    def block(self, scope_id: str, revocation: dict) -> dict:
        return self._request(
            "POST", f"/v2/scopes/{_id(scope_id)}/revoke",
            payload={"revocation": revocation},
        )
