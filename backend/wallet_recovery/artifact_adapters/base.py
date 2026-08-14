"""Common adapter contract. Secrets are never part of inspection results."""

from dataclasses import dataclass, field
from typing import Any, Dict, Protocol


@dataclass
class ArtifactInspection:
    adapter_id: str
    detected: bool
    encrypted: bool
    kdf: str | None = None
    cipher: str | None = None
    estimated_work: Dict[str, Any] = field(default_factory=dict)
    public_metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ArtifactPasswordResult:
    valid: bool
    public_evidence: Dict[str, Any] = field(default_factory=dict)
    estimated_work: Dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    secrets_discarded: bool = True


class ArtifactAdapter(Protocol):
    adapter_id: str

    def inspect(self, artifact: bytes | str | dict) -> ArtifactInspection: ...
    def estimate_work(self, artifact: bytes | str | dict) -> Dict[str, Any]: ...
    def verify_password_candidate(self, artifact: bytes | str | dict, password: str) -> ArtifactPasswordResult: ...
    def extract_public_evidence(self, artifact: bytes | str | dict, password: str) -> Dict[str, Any]: ...
    def recover(self, artifact: bytes | str | dict, password: str) -> ArtifactPasswordResult: ...
