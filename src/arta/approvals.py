"""HMAC-attested action-bound approvals for a trusted application boundary.

This module authenticates the integrity and issuance of an Approval record against a
shared secret. It does not authenticate the human by itself: the caller must authenticate
the user first and only then ask this authority to issue the approval.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import replace
from typing import Any

from .core import Approval, ApprovalStatus, MissionError, create_approval_record


class HmacApprovalAuthority:
    """Issue and verify approvals using a runtime-managed HMAC-SHA256 key.

    Keep the key in a secret manager or protected runtime configuration. Never commit it,
    return it to the model, or store it alongside approval records. Use separate keys for
    separate trust boundaries. This is symmetric attestation, not a public-key signature.
    """

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise MissionError("Approval HMAC key must be at least 32 bytes.")
        self._key = bytes(key)

    @staticmethod
    def _payload(approval: Approval) -> dict[str, Any]:
        if not isinstance(approval, Approval):
            raise MissionError("Approval must be an Approval record.")
        if not isinstance(approval.status, ApprovalStatus):
            raise MissionError("Approval status is invalid.")
        return {
            "schema": "arta.approval.v1",
            "approval_id": approval.approval_id,
            "approver_id": approval.approver_id,
            "action_fingerprint": approval.action_fingerprint,
            "approved_at": approval.approved_at,
            "expires_at": approval.expires_at,
            "status": approval.status.value,
        }

    def _signature(self, approval: Approval) -> str:
        try:
            message = json.dumps(
                self._payload(approval),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, AttributeError):
            raise MissionError("Approval cannot be represented as a canonical signed record.") from None
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def issue(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        *,
        approver_id: str,
        expires_at: str,
        approved_at: str | None = None,
        approval_id: str | None = None,
    ) -> Approval:
        """Create an approved record after the caller has authenticated approver_id."""
        approval = create_approval_record(
            tool_name,
            arguments,
            approver_id=approver_id,
            expires_at=expires_at,
            approved_at=approved_at,
            approval_id=approval_id,
        )
        return replace(approval, signature=self._signature(approval))

    def verify(self, approval: Approval) -> bool:
        """Return True only for an untampered, currently approved signed record."""
        if not isinstance(approval, Approval) or approval.status is not ApprovalStatus.APPROVED:
            return False
        signature = approval.signature
        if (
            not isinstance(signature, str)
            or len(signature) != 64
            or any(character not in "0123456789abcdef" for character in signature)
        ):
            return False
        try:
            expected = self._signature(approval)
        except (MissionError, TypeError, ValueError):
            return False
        return hmac.compare_digest(signature, expected)
