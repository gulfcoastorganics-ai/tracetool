"""Typed models for generation assurance and entropy-preservation evidence."""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class AssuranceLevel(str, Enum):
    VERIFIED_CONSTRUCTION = "VERIFIED_CONSTRUCTION"
    STRONG_EVIDENCE = "STRONG_EVIDENCE"
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    FAILED = "FAILED"


class CheckStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class FailurePolicy(str, Enum):
    FAIL_CLOSED = "FAIL_CLOSED"
    FAIL_OPEN_WEAK_RANDOMNESS = "FAIL_OPEN_WEAK_RANDOMNESS"
    UNKNOWN_FAILURE_POLICY = "UNKNOWN_FAILURE_POLICY"


class ClaimBasis(str, Enum):
    CONSTRUCTION_ONLY = "CONSTRUCTION_ONLY"
    TRUSTED_PLATFORM_CSPRNG = "TRUSTED_PLATFORM_CSPRNG"
    DOCUMENTED_VALIDATED_SOURCE = "DOCUMENTED_VALIDATED_SOURCE"
    EXTERNAL_ENTROPY_VALIDATION = "EXTERNAL_ENTROPY_VALIDATION"
    UNKNOWN = "UNKNOWN"


class EntropySourceKind(str, Enum):
    OS_CSPRNG = "OS_CSPRNG"
    WEB_CRYPTO = "WEB_CRYPTO"
    NODE_CRYPTO = "NODE_CRYPTO"
    PYTHON_SECRETS = "PYTHON_SECRETS"
    UNKNOWN = "UNKNOWN"


class EntropyClaim(BaseModel):
    nominal_bits: int = 0
    source_bits_requested: Optional[int] = None
    maximum_effective_bits: Optional[int] = None
    claimed_min_entropy: Optional[float] = None
    claim_basis: ClaimBasis = ClaimBasis.UNKNOWN
    confidence: float = Field(default=0, ge=0, le=1)
    statement: str = ""


class AssuranceCheck(BaseModel):
    id: str
    label: str
    status: CheckStatus
    mandatory: bool = True
    evidence: str = ""
    location: Optional[str] = None


class SourceAuditRequest(BaseModel):
    source: str = Field(min_length=1, max_length=300_000)
    filename: str = "snippet.py"
    implementation: Optional[str] = None
    platform: Optional[str] = None
    runtime: Optional[str] = None


class SourceAuditFinding(BaseModel):
    file: str
    line: int
    category: str
    status: CheckStatus
    evidence: str
    recommendation: str


class SourceAuditResult(BaseModel):
    filename: str
    implementation: Optional[str] = None
    platform: Optional[str] = None
    runtime: Optional[str] = None
    source_kind: EntropySourceKind
    source_bits_requested: Optional[int] = None
    consumed_bits: Optional[int] = None
    discarded_bits: int = 0
    final_output_bits: Optional[int] = None
    maximum_effective_bits: Optional[int] = None
    failure_policy: FailurePolicy = FailurePolicy.UNKNOWN_FAILURE_POLICY
    findings: List[SourceAuditFinding] = Field(default_factory=list)
    positive_evidence: List[str] = Field(default_factory=list)
    data_flow: List[str] = Field(default_factory=list)
    assurance: AssuranceLevel = AssuranceLevel.INSUFFICIENT_EVIDENCE
    claim: EntropyClaim = Field(default_factory=EntropyClaim)
    statistical_tests_are_supplementary: bool = True


class PipelineEvidence(BaseModel):
    source_type: EntropySourceKind = EntropySourceKind.UNKNOWN
    source_bits_requested: Optional[int] = None
    consumed_bits: Optional[int] = None
    discarded_bits: int = 0
    final_output_bits: Optional[int] = None
    transformations: List[str] = Field(default_factory=list)
    failure_policy: FailurePolicy = FailurePolicy.UNKNOWN_FAILURE_POLICY
    complete_initialization: Optional[bool] = None
    environment: Optional[str] = None


class BIP39ValidationResult(BaseModel):
    valid: bool
    entropy_bits: Optional[int] = None
    checksum_bits: Optional[int] = None
    mnemonic_words: Optional[int] = None
    entropy_hex: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)


class RuntimeProbeResult(BaseModel):
    environment: str
    runtime: str
    api_available: bool
    request_succeeded: bool
    bytes_returned: int = 0
    requested_bytes: int = 32
    fallback_activated: bool = False
    status: CheckStatus
    notes: List[str] = Field(default_factory=list)


class EnvironmentReport(BaseModel):
    implementation: Optional[str] = None
    platform: str
    runtime: str
    generator_code_path: Optional[str] = None
    entropy_api: Optional[str] = None
    library_versions: Dict[str, str] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


class DiagnosticResult(BaseModel):
    sample_count: int
    duplicate_blocks: int
    constant_output: bool
    repeated_prefixes: int
    status: CheckStatus
    label: str = "SUPPLEMENTARY_DIAGNOSTICS"
    note: str = "Absence of collisions does not prove cryptographic entropy."


class AssuranceReport(BaseModel):
    nominal_entropy_bits: int
    claimed_entropy_bits: Optional[int] = None
    preserved_entropy_bits: Optional[int] = None
    entropy_source_assurance: AssuranceLevel
    implementation_assurance: AssuranceLevel
    environment_assurance: AssuranceLevel
    overall_assurance: AssuranceLevel
    source_type: EntropySourceKind
    source_bits_requested: Optional[int] = None
    consumed_bits: Optional[int] = None
    discarded_bits: int = 0
    maximum_effective_bits: Optional[int] = None
    failure_policy: FailurePolicy
    bip39: Optional[BIP39ValidationResult] = None
    checks: List[AssuranceCheck] = Field(default_factory=list)
    findings: List[SourceAuditFinding] = Field(default_factory=list)
    data_flow: List[str] = Field(default_factory=list)
    runtime_probe: Optional[RuntimeProbeResult] = None
    environment: Optional[EnvironmentReport] = None
    diagnostics: Optional[DiagnosticResult] = None
    claim: EntropyClaim
    recommendation: str
    created_at: str


class GeneratorAuditRequest(SourceAuditRequest):
    bip39_entropy_hex: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    run_diagnostics: bool = False


class RuntimeProbeRequest(BaseModel):
    environment: str = "python-native"
    runtime: str = "CPython"
    api: str = "secrets.token_bytes"
    requested_bytes: int = Field(default=32, ge=1, le=64)


class CompareRequest(BaseModel):
    mode: str = Field(default="standard", pattern=r"^(standard|expanded|truncated|weak32)$")


class SelfAuditRequest(BaseModel):
    include_mnemonic: bool = False

