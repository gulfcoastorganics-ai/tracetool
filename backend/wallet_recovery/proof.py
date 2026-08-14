"""Multi-source public recovery proof bundles."""

from dataclasses import dataclass, field


@dataclass
class RecoveryProofBundle:
    cryptographic_certainty: str = "NONE"
    evidence_sources: list[str] = field(default_factory=list)
    independent_public_matches: int = 0
    findings: list[str] = field(default_factory=list)

    def add(self, source: str, finding: str, *, decisive=False):
        if source not in self.evidence_sources: self.evidence_sources.append(source)
        self.independent_public_matches += 1
        self.findings.append(finding)
        if decisive: self.cryptographic_certainty = "EXACT"

    def sanitized(self):
        return {"cryptographic_certainty": self.cryptographic_certainty, "evidence_sources": list(self.evidence_sources), "independent_public_matches": self.independent_public_matches, "findings": list(self.findings), "secrets": "REDACTED"}
