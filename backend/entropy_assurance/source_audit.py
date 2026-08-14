"""Static entropy-source and failure-path audit.

This is deliberately conservative: regex evidence supports a review result but
does not prove the behavior of arbitrary code or its platform implementation.
"""

import re

from .models import (
    AssuranceLevel, CheckStatus, EntropyClaim, EntropySourceKind, FailurePolicy,
    SourceAuditFinding, SourceAuditRequest, SourceAuditResult,
)


def _finding(filename, line, category, status, evidence, recommendation):
    return SourceAuditFinding(file=filename, line=line, category=category, status=status, evidence=evidence[:300], recommendation=recommendation)


def _line_for(source: str, pattern: str) -> int:
    match = re.search(pattern, source, re.IGNORECASE | re.DOTALL)
    return source.count("\n", 0, match.start()) + 1 if match else 1


def audit_source(request: SourceAuditRequest) -> SourceAuditResult:
    source = request.source
    lowered = source.lower()
    findings: list[SourceAuditFinding] = []
    positive: list[str] = []
    flow: list[str] = []
    source_kind = EntropySourceKind.UNKNOWN
    requested: int | None = None

    if re.search(r"secrets\.token_bytes\s*\(\s*32\s*\)", source):
        source_kind, requested = EntropySourceKind.PYTHON_SECRETS, 256
        positive.append("secrets.token_bytes(32)")
    elif re.search(r"os\.urandom\s*\(\s*32\s*\)", source):
        source_kind, requested = EntropySourceKind.OS_CSPRNG, 256
        positive.append("os.urandom(32)")
    elif re.search(r"crypto\.randomBytes\s*\(\s*32\s*\)", source):
        source_kind, requested = EntropySourceKind.NODE_CRYPTO, 256
        positive.append("crypto.randomBytes(32)")
    elif re.search(r"(?:globalThis\.)?crypto\.getRandomValues\s*\(.*?(?:Uint8Array|Uint8ClampedArray)\s*\(\s*32\s*\)", source, re.DOTALL):
        source_kind, requested = EntropySourceKind.WEB_CRYPTO, 256
        positive.append("crypto.getRandomValues(new Uint8Array(32))")

    weak_patterns = [
        (r"\brandom\.random\s*\(|\bMath\.random\s*\(", "WEAK_RANDOM_API", "Do not use non-cryptographic random APIs for wallet entropy."),
        (r"\brandom\.getrandbits\s*\(|\brandom\.Random\s*\(", "PYTHON_RANDOM", "Use secrets or os.urandom and fail closed."),
        (r"\b(?:MT19937|MersenneTwister|mulberry32|xorshift|alea)\b", "LOW_STATE_PRNG", "Remove custom or low-state PRNGs from secret generation."),
        (r"(?:Date\.now|performance\.now|time\.time)\s*\(?.{0,80}(?:seed|random|rng)", "TIME_SEED", "Never seed wallet entropy from time."),
        (r"(?:process\.pid|os\.getpid)\s*\(?.{0,80}(?:seed|random|rng)", "PID_SEED", "PID is not an entropy source."),
        (r"(?:fixed|constant|hard.?coded)\s+seed|seed\s*=\s*[0-9]+", "FIXED_SEED", "Remove fixed seeds and deterministic initialization."),
    ]
    for pattern, category, recommendation in weak_patterns:
        match = re.search(pattern, source, re.IGNORECASE | re.DOTALL)
        if match:
            findings.append(_finding(request.filename, source.count("\n", 0, match.start()) + 1, category, CheckStatus.FAIL, match.group(0), recommendation))

    fallback = re.search(r"(?:catch|except)[^{\n]*(?:\{|:)?[\s\S]{0,500}(?:math\.random|random\.random|random\.getrandbits|date\.now|time\.time|fallback|fillusingmathrandom)", source, re.IGNORECASE)
    if fallback:
        failure_policy = FailurePolicy.FAIL_OPEN_WEAK_RANDOMNESS
        findings.append(_finding(request.filename, source.count("\n", 0, fallback.start()) + 1, "WEAK_FALLBACK", CheckStatus.FAIL, fallback.group(0), "Abort generation when cryptographic randomness fails."))
    elif re.search(r"(?:raise|throw|abort|return\s+(?:None|null|false))", source, re.IGNORECASE) and re.search(r"(?:catch|except)", source, re.IGNORECASE):
        failure_policy = FailurePolicy.FAIL_CLOSED
        positive.append("failure path aborts or raises")
    else:
        failure_policy = FailurePolicy.UNKNOWN_FAILURE_POLICY

    # Width and state reduction heuristics.
    maximum = requested
    consumed = requested
    discarded = 0
    if re.search(r"(?:token_bytes|urandom|randomBytes|getRandomValues)\s*\(\s*(?:16|16\s*\)|['\"]16)", source, re.IGNORECASE):
        requested = consumed = 128
        maximum = 128
        findings.append(_finding(request.filename, _line_for(source, r"(?:token_bytes|urandom|randomBytes|getRandomValues)\s*\(\s*16"), "SHORT_SOURCE", CheckStatus.FAIL, "16 random bytes requested", "Request exactly 32 cryptographic random bytes for a 256-bit target."))
    if re.search(r"(?:token_bytes|urandom|randomBytes|getRandomValues)\s*\(\s*(?:4|8)\s*\)", source, re.IGNORECASE):
        requested = consumed = 32 if "4" in re.search(r"\((?:\s*4|\s*8)", source).group(0) else 64
        maximum = requested
        findings.append(_finding(request.filename, _line_for(source, r"(?:token_bytes|urandom|randomBytes|getRandomValues)\s*\(\s*(?:4|8)"), "LOW_WIDTH_SOURCE", CheckStatus.FAIL, "low-width random request", "Request 32 random bytes; hashing cannot create missing entropy."))
    slice_match = re.search(r"(?:slice|subarray)\s*\(\s*0\s*,\s*(8|16|4)\s*\)|\[:\s*(8|16|4)\s*\]", source, re.IGNORECASE)
    if slice_match:
        retained_bytes = int(next(item for item in slice_match.groups() if item))
        discarded = max(0, 256 - retained_bytes * 8)
        maximum = min(maximum or 256, retained_bytes * 8)
        findings.append(_finding(request.filename, source.count("\n", 0, slice_match.start()) + 1, "ENTROPY_TRUNCATION", CheckStatus.FAIL, slice_match.group(0), "Do not discard random input before BIP39 construction."))
    if re.search(r"(?:sha256|createHash\s*\(\s*['\"]sha256).{0,100}(?:seed|random|rand|4\s*bytes|32-bit)", source, re.IGNORECASE | re.DOTALL):
        seed_bits = 32 if re.search(r"(?:4\s*bytes|32-bit|uint32|random\.getrandbits\s*\(\s*32)", source, re.IGNORECASE) else (maximum or 256)
        maximum = min(maximum or seed_bits, seed_bits)
        findings.append(_finding(request.filename, _line_for(source, r"sha256|createHash\s*\(\s*['\"]sha256"), "DETERMINISTIC_EXPANSION", CheckStatus.FAIL, "smaller state is hashed into a wider output", "Track source entropy; a hash expands representation, not uncertainty."))
    if requested == 256 and maximum == 256:
        flow.extend(["cryptographic source requests 32 bytes", "32 bytes = 256 input bits", "no detected width reduction"])
    elif maximum is not None:
        flow.append(f"maximum effective entropy bounded at {maximum} bits")
    if source_kind == EntropySourceKind.UNKNOWN:
        findings.append(_finding(request.filename, 1, "NO_RECOGNIZED_CSPRNG", CheckStatus.UNKNOWN, "No recognized cryptographic entropy API", "Provide an auditable platform CSPRNG call."))

    if requested == 256 and not findings and failure_policy == FailurePolicy.FAIL_CLOSED:
        assurance = AssuranceLevel.STRONG_EVIDENCE
    elif any(item.status == CheckStatus.FAIL for item in findings):
        assurance = AssuranceLevel.FAILED
    elif source_kind != EntropySourceKind.UNKNOWN:
        assurance = AssuranceLevel.PARTIAL_EVIDENCE
    else:
        assurance = AssuranceLevel.INSUFFICIENT_EVIDENCE
    claim_basis = "TRUSTED_PLATFORM_CSPRNG" if source_kind != EntropySourceKind.UNKNOWN and requested == 256 else "CONSTRUCTION_ONLY"
    claim = EntropyClaim(nominal_bits=256, source_bits_requested=requested, maximum_effective_bits=maximum, claim_basis=claim_basis, confidence=0.9 if assurance == AssuranceLevel.STRONG_EVIDENCE else 0.35, statement="Supports a 256-bit target under the trusted platform CSPRNG assumption." if requested == 256 and assurance != AssuranceLevel.FAILED else "No 256-bit assurance claim established.")
    return SourceAuditResult(filename=request.filename, implementation=request.implementation, platform=request.platform, runtime=request.runtime, source_kind=source_kind, source_bits_requested=requested, consumed_bits=consumed, discarded_bits=discarded, final_output_bits=256 if re.search(r"(?:32|256)", source) else None, maximum_effective_bits=maximum, failure_policy=failure_policy, findings=findings, positive_evidence=positive, data_flow=flow, assurance=assurance, claim=claim)
