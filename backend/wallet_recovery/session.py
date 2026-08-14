"""Short-lived in-memory owner recovery sessions."""

import secrets
import time

from .models import RecoverySessionResponse, WalletEvidence


class RecoverySessionStore:
    def __init__(self):
        self._sessions: dict[str, dict] = {}

    def create(self, evidence: WalletEvidence, ttl_seconds: int):
        token = f"ct-recovery-{secrets.token_urlsafe(32)}"
        self._sessions[token] = {"evidence": evidence, "expires_at": time.time() + ttl_seconds}
        return token

    def get(self, token: str):
        record = self._sessions.get(token)
        if not record:
            raise ValueError("Recovery session is invalid or expired")
        if record["expires_at"] <= time.time():
            self._sessions.pop(token, None)
            raise ValueError("Recovery session is invalid or expired")
        return record["evidence"]

    def close(self, token: str):
        self._sessions.pop(token, None)


recovery_sessions = RecoverySessionStore()
