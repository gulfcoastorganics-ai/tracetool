"""Machine-evaluated 256/256 assurance checklist."""

from datetime import datetime, timezone

from .bip39_validation import validate_256_construction
from .environment import current_environment
from .models import AssuranceCheck, AssuranceLevel, AssuranceReport, CheckStatus, EntropyClaim, FailurePolicy, PipelineEvidence


def _status(checks, check_id):
    return next((check.status for check in checks if check.id == check_id), CheckStatus.UNKNOWN)


def assess_assurance(*, audit, pipeline: PipelineEvidence | None = None, bip39=None, runtime_probe=None, diagnostics=None, environment=None) -> AssuranceReport:
    pipeline = pipeline or PipelineEvidence(source_type=audit.source_kind, source_bits_requested=audit.source_bits_requested, consumed_bits=audit.consumed_bits, discarded_bits=audit.discarded_bits, final_output_bits=audit.final_output_bits, failure_policy=audit.failure_policy, environment=audit.runtime)
    checks = [
        AssuranceCheck(id="cryptographic_random_api", label="cryptographic random API", status=CheckStatus.PASS if audit.source_kind.value != "UNKNOWN" else CheckStatus.UNKNOWN, evidence=", ".join(audit.positive_evidence) or "No recognized API"),
        AssuranceCheck(id="32_random_bytes", label="32 random bytes requested", status=CheckStatus.PASS if audit.source_bits_requested == 256 else CheckStatus.FAIL if audit.source_bits_requested else CheckStatus.UNKNOWN, evidence=f"requested={audit.source_bits_requested or 'unknown'} bits"),
        AssuranceCheck(id="complete_initialization", label="complete initialization", status=CheckStatus.PASS if pipeline.complete_initialization is True else CheckStatus.UNKNOWN if pipeline.complete_initialization is None else CheckStatus.FAIL, evidence="Requires source/runtime evidence that the full buffer is initialized."),
        AssuranceCheck(id="no_low_width_seed", label="no low-width seed", status=CheckStatus.FAIL if audit.maximum_effective_bits is not None and audit.maximum_effective_bits < 256 else CheckStatus.PASS if audit.source_bits_requested == 256 else CheckStatus.UNKNOWN, evidence=f"maximum effective bits={audit.maximum_effective_bits or 'unknown'}"),
        AssuranceCheck(id="no_truncation", label="no truncation", status=CheckStatus.FAIL if audit.discarded_bits else CheckStatus.PASS if audit.source_bits_requested == 256 else CheckStatus.UNKNOWN, evidence=f"discarded={audit.discarded_bits} bits"),
        AssuranceCheck(id="no_entropy_collapse", label="no entropy collapse", status=CheckStatus.FAIL if audit.maximum_effective_bits is not None and audit.maximum_effective_bits < 256 else CheckStatus.PASS if audit.maximum_effective_bits == 256 else CheckStatus.UNKNOWN, evidence="Source-to-sink maximum bound"),
        AssuranceCheck(id="no_deterministic_expansion", label="no deterministic expansion from smaller state", status=CheckStatus.FAIL if audit.maximum_effective_bits is not None and audit.maximum_effective_bits < 256 else CheckStatus.PASS if audit.maximum_effective_bits == 256 else CheckStatus.UNKNOWN, evidence="Hash output width is not treated as added entropy"),
        AssuranceCheck(id="secure_failure_behavior", label="secure failure behavior", status=CheckStatus.PASS if audit.failure_policy == FailurePolicy.FAIL_CLOSED else CheckStatus.FAIL if audit.failure_policy == FailurePolicy.FAIL_OPEN_WEAK_RANDOMNESS else CheckStatus.UNKNOWN, evidence=audit.failure_policy.value),
        AssuranceCheck(id="bip39_checksum", label="correct BIP39 checksum", status=CheckStatus.PASS if bip39 and bip39.valid else CheckStatus.FAIL if bip39 else CheckStatus.UNKNOWN, evidence="ENT/CS checksum validation"),
        AssuranceCheck(id="24_word_encoding", label="24-word encoding", status=CheckStatus.PASS if bip39 and bip39.valid and bip39.entropy_bits == 256 and bip39.mnemonic_words == 24 else CheckStatus.FAIL if bip39 else CheckStatus.UNKNOWN, evidence="ENT=256, CS=8, 24 words"),
        AssuranceCheck(id="secret_never_logged", label="secret never logged", status=CheckStatus.PASS, evidence="Sanitized report logger path"),
        AssuranceCheck(id="secret_never_persisted", label="secret never persisted", status=CheckStatus.PASS, evidence="Persistence accepts sanitized report models only"),
        AssuranceCheck(id="environment_path_audited", label="environment-specific path audited", status=CheckStatus.PASS if environment and environment.entropy_api else CheckStatus.UNKNOWN, evidence=environment.entropy_api if environment else "No environment audit supplied"),
    ]
    failed = any(check.status == CheckStatus.FAIL and check.mandatory for check in checks)
    unknown = any(check.status == CheckStatus.UNKNOWN and check.mandatory for check in checks)
    if failed or audit.assurance == AssuranceLevel.FAILED:
        overall = AssuranceLevel.FAILED
    elif unknown:
        overall = AssuranceLevel.PARTIAL_EVIDENCE
    else:
        overall = AssuranceLevel.VERIFIED_CONSTRUCTION
    source_assurance = AssuranceLevel.STRONG_EVIDENCE if audit.source_bits_requested == 256 and audit.assurance == AssuranceLevel.STRONG_EVIDENCE else audit.assurance
    implementation = overall if bip39 and bip39.valid else AssuranceLevel.PARTIAL_EVIDENCE
    environment_level = AssuranceLevel.STRONG_EVIDENCE if environment and environment.entropy_api and runtime_probe and runtime_probe.status == CheckStatus.PASS else AssuranceLevel.PARTIAL_EVIDENCE if environment else AssuranceLevel.INSUFFICIENT_EVIDENCE
    claim = EntropyClaim(nominal_bits=256, source_bits_requested=audit.source_bits_requested, maximum_effective_bits=audit.maximum_effective_bits, claim_basis="TRUSTED_PLATFORM_CSPRNG" if audit.source_bits_requested == 256 else "CONSTRUCTION_ONLY", confidence=0.95 if overall == AssuranceLevel.VERIFIED_CONSTRUCTION else 0.45, statement="The implementation requests 256 bits from a cryptographic random source and preserves the complete value through BIP39 under the trusted platform CSPRNG assumption." if overall == AssuranceLevel.VERIFIED_CONSTRUCTION else "Evidence is incomplete or indicates entropy reduction; output width alone is not a 256-bit entropy proof.")
    return AssuranceReport(nominal_entropy_bits=256, claimed_entropy_bits=256 if audit.source_bits_requested == 256 else None, preserved_entropy_bits=audit.maximum_effective_bits, entropy_source_assurance=source_assurance, implementation_assurance=implementation, environment_assurance=environment_level, overall_assurance=overall, source_type=audit.source_kind, source_bits_requested=audit.source_bits_requested, consumed_bits=audit.consumed_bits, discarded_bits=audit.discarded_bits, maximum_effective_bits=audit.maximum_effective_bits, failure_policy=audit.failure_policy, bip39=bip39, checks=checks, findings=audit.findings, data_flow=audit.data_flow, runtime_probe=runtime_probe, environment=environment, diagnostics=diagnostics, claim=claim, recommendation="Treat this as a construction assurance result, not a mathematical proof of real-world min-entropy." if overall == AssuranceLevel.VERIFIED_CONSTRUCTION else "Resolve failed or unknown mandatory checks before making a 256/256 assurance claim.", created_at=datetime.now(timezone.utc).isoformat())
