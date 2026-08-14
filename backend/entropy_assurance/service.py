"""Service facade for source audits, self-audit, probes, and comparisons."""

import hashlib
import logging
import secrets
from collections import Counter

from .assurance import assess_assurance
from .bip39_validation import validate_256_construction
from .environment import current_environment
from .models import (
    CheckStatus, CompareRequest, DiagnosticResult, EntropySourceKind, GeneratorAuditRequest,
    PipelineEvidence, RuntimeProbeRequest, SelfAuditRequest, SourceAuditRequest,
)
from .report import persist_report
from .runtime_probe import probe_environment, probe_python
from .source_audit import audit_source
from .preservation import preserved_entropy
from hdwallet.mnemonics import BIP39Mnemonic

logger = logging.getLogger("chain_trace.entropy_assurance")


def diagnostics(sample_count=32):
    blocks = [secrets.token_bytes(32) for _ in range(min(sample_count, 64))]
    counts = Counter(blocks)
    prefixes = Counter(block[:4] for block in blocks)
    duplicate_blocks = sum(value - 1 for value in counts.values() if value > 1)
    repeated_prefixes = sum(value - 1 for value in prefixes.values() if value > 1)
    constant = len(counts) <= 1
    return DiagnosticResult(sample_count=len(blocks), duplicate_blocks=duplicate_blocks, constant_output=constant, repeated_prefixes=repeated_prefixes, status=CheckStatus.FAIL if constant else CheckStatus.WARNING if duplicate_blocks else CheckStatus.PASS)


class EntropyAssuranceService:
    def audit_source(self, request: SourceAuditRequest):
        result = audit_source(request)
        logger.info("entropy_assurance_source_audit file=%s assurance=%s", request.filename, result.assurance.value)
        return result

    def audit_generator(self, request: GeneratorAuditRequest):
        audit = audit_source(request)
        bip39 = validate_256_construction(request.bip39_entropy_hex) if request.bip39_entropy_hex else None
        environment = current_environment(implementation=request.implementation, generator_code_path=request.filename, entropy_api=audit.source_kind.value, runtime=request.runtime)
        probe = probe_python(32, environment="python-native", runtime=request.runtime or "CPython") if audit.source_kind in (EntropySourceKind.PYTHON_SECRETS, EntropySourceKind.OS_CSPRNG) else None
        result = assess_assurance(audit=audit, pipeline=PipelineEvidence(source_type=audit.source_kind, source_bits_requested=audit.source_bits_requested, consumed_bits=audit.consumed_bits, discarded_bits=audit.discarded_bits, final_output_bits=audit.final_output_bits, failure_policy=audit.failure_policy, complete_initialization=True if audit.source_bits_requested == 256 and audit.discarded_bits == 0 else False, environment=request.platform), bip39=bip39, runtime_probe=probe, environment=environment)
        persist_report(result)
        return result

    def runtime_probe(self, request: RuntimeProbeRequest):
        return probe_environment(request.environment, request.runtime, request.api, request.requested_bytes)

    def self_audit(self, request: SelfAuditRequest):
        # The source text is an auditable reference construction. The mnemonic is generated and discarded.
        secure_source = """def generate():
    try:
        entropy = secrets.token_bytes(32)
    except Exception as exc:
        raise RuntimeError('CSPRNG unavailable') from exc
    return entropy
"""
        audit = audit_source(SourceAuditRequest(source=secure_source, filename="chain_trace_reference_generator.py", implementation="Chain-Trace reference generator", platform="native Python", runtime="CPython"))
        entropy = secrets.token_bytes(32)
        mnemonic = BIP39Mnemonic.from_entropy(entropy, "english")
        bip39 = validate_256_construction(entropy.hex())
        probe = probe_python(32)
        environment = current_environment(implementation="Chain-Trace reference generator", generator_code_path="chain_trace_reference_generator.py", entropy_api="PYTHON_SECRETS", runtime="CPython")
        result = assess_assurance(audit=audit, pipeline=PipelineEvidence(source_type=EntropySourceKind.PYTHON_SECRETS, source_bits_requested=256, consumed_bits=256, discarded_bits=0, final_output_bits=256, failure_policy=audit.failure_policy, complete_initialization=True, environment="native Python"), bip39=bip39, runtime_probe=probe, environment=environment)
        persist_report(result)
        # Explicitly discard local secrets before returning. include_mnemonic is opt-in and never persisted/logged.
        if not request.include_mnemonic:
            del mnemonic
        del entropy
        return result

    def compare(self, request: CompareRequest):
        cases = {
            "standard": (256, 256, 0, "OS CSPRNG → 32 random bytes → BIP39 → 24 words"),
            "expanded": (32, 32, 0, "32-bit deterministic seed → SHA256 → 256-bit output"),
            "truncated": (256, 64, 192, "256 random bits → retain 64 bits → SHA256"),
            "weak32": (32, 32, 0, "32-bit PRNG seed → deterministic PRNG → 32-byte output"),
        }
        source, preserved, discarded, construction = cases[request.mode]
        flow = preserved_entropy(source_bits=source, consumed_bits=preserved, discarded_bits=discarded, final_output_bits=256, transformations=[construction])
        return {"mode": request.mode, "construction": construction, "source_bits": source, "maximum_effective_bits": flow["maximum_effective_bits"], "final_output_bits": 256, "status": "PASS" if flow["maximum_effective_bits"] == 256 else "FAIL", "warning": "Output width does not equal entropy. Hashing cannot recreate discarded or absent uncertainty.", "data_flow": flow}


assurance_service = EntropyAssuranceService()
