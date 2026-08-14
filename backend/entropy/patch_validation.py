"""Static-only checks for entropy-generation source snippets."""

import re

from .models import EntropyClassification, EntropySource, SourceAuditFinding


RULES = [
    (r"\bMath\.random\s*\(", EntropySource.WEAK_PRNG, "high", "Replace with Web Crypto getRandomValues or a reviewed OS CSPRNG API."),
    (r"\b(?:import\s+random|from\s+random\s+import)", EntropySource.WEAK_PRNG, "high", "Python random is not a cryptographic secret generator; use secrets or os.urandom."),
    (r"\b(?:MT19937|MersenneTwister|mersenne_twister)", EntropySource.WEAK_PRNG, "high", "Do not use MT19937 for wallet secrets."),
    (r"(?:fixed|constant|hard.?coded)\s+(?:seed|entropy)|seed\s*=\s*[0-9]+", EntropySource.DETERMINISTIC, "critical", "Remove fixed seed material and fail closed on RNG errors."),
    (r"(?:time\.time|Date\.now|timestamp).{0,40}(?:seed|random|rng)", EntropySource.TIMESTAMP, "critical", "Do not derive secret state from timestamps."),
    (r"(?:fallback|except).{0,80}(?:0{3,}|seed|random)", EntropySource.DETERMINISTIC, "critical", "RNG failure fallback must fail closed, not become deterministic."),
    (r"(?:truncate|slice|substring|\[:\s*(?:2|4|8|16)\s*\]).{0,50}(?:random|entropy|bytes)", EntropySource.TRUNCATED_CSPRNG, "high", "Preserve sufficient CSPRNG output; document any deliberate security bound."),
]
POSITIVE = [
    (r"os\.urandom|(?:secrets\.)?(?:token_bytes|token_hex|randbits)", "OS CSPRNG"),
    (r"getrandom\s*\(", "Linux getrandom"),
    (r"crypto\.getRandomValues|window\.crypto\.getRandomValues", "Web Crypto CSPRNG"),
]


def audit_source(source: str, filename: str = "snippet.py"):
    findings = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for pattern, source_type, risk, recommendation in RULES:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(SourceAuditFinding(file=filename, line=line_number, generator_function=None, entropy_source=source_type, risk=risk, evidence=line.strip()[:240], recommendation=recommendation))
    positives = []
    for pattern, label in POSITIVE:
        for match in re.finditer(pattern, source, re.IGNORECASE):
            positives.append({"label": label, "offset": match.start()})
    risk = EntropyClassification.KNOWN_VULNERABLE_GENERATOR if any(item.risk in ("critical", "high") for item in findings) else EntropyClassification.SECURE_EXPECTED if positives else EntropyClassification.INSUFFICIENT_EVIDENCE
    return findings, positives, risk


def validate_source(source: str, filename: str = "snippet.py"):
    findings, positives, risk = audit_source(source, filename)
    return {"findings": [item.model_dump() for item in findings], "positive_evidence": positives, "risk": risk, "secure_detection_not_proof": True}
