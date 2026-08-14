"""Typed domain models for Entropy Intelligence."""

from datetime import date
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class EntropyClassification(str, Enum):
    SECURE_EXPECTED = "SECURE_EXPECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    REDUCED_ENTROPY = "REDUCED_ENTROPY"
    KNOWN_VULNERABLE_GENERATOR = "KNOWN_VULNERABLE_GENERATOR"
    PARTIAL_RECOVERY_SCENARIO = "PARTIAL_RECOVERY_SCENARIO"
    PATCHED_SOFTWARE_OLD_WALLETS_AT_RISK = "PATCHED_SOFTWARE_OLD_WALLETS_AT_RISK"
    INFEASIBLE_SEARCH_SPACE = "INFEASIBLE_SEARCH_SPACE"
    BOUNDED_RECOVERY_PLAUSIBLE = "BOUNDED_RECOVERY_PLAUSIBLE"


class FeasibilityClass(str, Enum):
    TRIVIAL_LAB = "TRIVIAL_LAB"
    SMALL_BOUNDED = "SMALL_BOUNDED"
    PRACTICAL_WITH_CONSTRAINTS = "PRACTICAL_WITH_CONSTRAINTS"
    EXPENSIVE = "EXPENSIVE"
    COMPUTATIONALLY_INFEASIBLE = "COMPUTATIONALLY_INFEASIBLE"
    UNKNOWN = "UNKNOWN"


class EntropySource(str, Enum):
    OS_CSPRNG = "OS_CSPRNG"
    WEB_CRYPTO = "WEB_CRYPTO"
    WEAK_PRNG = "WEAK_PRNG"
    TIMESTAMP = "TIMESTAMP"
    DETERMINISTIC = "DETERMINISTIC"
    HUMAN_CHOSEN = "HUMAN_CHOSEN"
    TRUNCATED_CSPRNG = "TRUNCATED_CSPRNG"
    UNKNOWN = "UNKNOWN"


class PatchStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    PATCHED = "PATCHED"
    VULNERABLE = "VULNERABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class WeaknessClass(str, Enum):
    WEAK_BROWSER_WASM_PRNG = "weak_browser_wasm_prng"
    LOW_WIDTH_SEED = "low_width_seed"
    TIMESTAMP_SEEDED = "timestamp_seeded"
    MATH_RANDOM = "math_random_style"
    DETERMINISTIC_FALLBACK = "deterministic_fallback"
    BRAINWALLET = "brainwallet"


class AffectedVersionRange(BaseModel):
    minimum: Optional[str] = None
    maximum: Optional[str] = None
    affected_period: Optional[str] = None


class WalletProvenance(BaseModel):
    wallet_software: Optional[str] = None
    wallet_version: Optional[str] = None
    platform: Optional[str] = None
    creation_date: Optional[date] = None
    generator_details: Optional[str] = None
    implementation_fingerprint: Optional[str] = None
    rng_function: Optional[str] = None
    prng_state_width_bits: Optional[int] = Field(default=None, ge=1, le=4096)
    source_code_evidence: Optional[str] = None


class GeneratorEvidence(BaseModel):
    statement: str
    source: str = "user"
    supports: bool = True
    confidence: float = Field(default=0.5, ge=0, le=1)


class KnownConstraint(BaseModel):
    name: str
    description: str
    entropy_reduction_bits: float = Field(default=0, ge=0)
    confidence: float = Field(default=0.5, ge=0, le=1)


class EntropyEstimate(BaseModel):
    nominal_entropy_bits: Optional[float] = None
    estimated_effective_entropy_bits: Optional[float] = None
    estimated_candidate_space: Optional[int] = None
    candidate_space_display: str
    evidence_confidence: float = Field(ge=0, le=1)
    reasoning_factors: List[str] = Field(default_factory=list)
    classification: EntropyClassification
    feasibility_class: FeasibilityClass
    checksum_bits: int = 0
    illustrative_rate_candidates_per_second: Optional[float] = None
    illustrative_full_space_seconds: Optional[float] = None


class VulnerabilityProfile(BaseModel):
    id: str
    name: str
    wallet_or_tool: str
    affected_platform: str
    affected_versions: AffectedVersionRange
    affected_period: Optional[str] = None
    weakness_class: WeaknessClass
    entropy_source: EntropySource
    effective_entropy_description: str
    known_state_width_bits: Optional[int] = None
    remediation_version: Optional[str] = None
    old_generated_wallets_remain_exposed: bool = True
    references: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0, le=1)


class EntropyAnalysisRequest(BaseModel):
    provenance: WalletProvenance = Field(default_factory=WalletProvenance)
    mnemonic_length: Optional[int] = Field(default=None, ge=1, le=48)
    nominal_entropy_bits: Optional[int] = Field(default=None, ge=1, le=4096)
    unknown_mnemonic_words: Optional[int] = Field(default=None, ge=0, le=48)
    known_word_positions: List[int] = Field(default_factory=list)
    known_derivation_path: Optional[str] = None
    known_address: Optional[str] = None
    passphrase_known: Optional[bool] = None
    generator_state_width_bits: Optional[int] = Field(default=None, ge=1, le=4096)
    disclosed_prng_weakness: Optional[str] = None
    documented_generator_state_reduction: Optional[float] = Field(default=None, ge=0)
    constraints: List[KnownConstraint] = Field(default_factory=list)
    evidence: List[GeneratorEvidence] = Field(default_factory=list)
    software_status: PatchStatus = PatchStatus.UNKNOWN
    wallet_generation_status: PatchStatus = PatchStatus.UNKNOWN


class FeasibilityAssessment(BaseModel):
    feasibility_class: FeasibilityClass
    explanation: str
    warnings: List[str] = Field(default_factory=list)


class EntropyAnalysisResult(BaseModel):
    provenance: WalletProvenance
    likely_generator_profile: Optional[VulnerabilityProfile] = None
    possible_generator_profiles: List[VulnerabilityProfile] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    generator_confidence: float = Field(ge=0, le=1)
    effective_entropy_impact: str
    estimate: EntropyEstimate
    feasibility: FeasibilityAssessment
    software_status: PatchStatus
    wallet_generation_status: PatchStatus
    existing_wallet_entropy_repaired: bool = False
    recommended_response: str


class SyntheticWeakGeneratorConfig(BaseModel):
    model: str = Field(pattern=r"^(16|20|24|32|timestamp|repeated|truncated|patched)$")
    target_position: Optional[int] = Field(default=None, ge=0)
    address_type: str = Field(default="p2pkh", pattern=r"^(p2pkh|p2wpkh)$")


class SyntheticWeakGeneratorResult(BaseModel):
    session_token: str
    model: str
    target_address: str
    address_type: str
    nominal_entropy_bits: int
    actual_effective_entropy_bits: int
    candidate_space: int
    candidate_space_display: str
    feasibility_class: FeasibilityClass
    recovery_allowed: bool
    secret_redacted: bool = True


class PatchValidationResult(BaseModel):
    findings: List[Dict[str, object]] = Field(default_factory=list)
    positive_evidence: List[Dict[str, object]] = Field(default_factory=list)
    risk: EntropyClassification
    secure_detection_not_proof: bool = True


class PartialMnemonicRequest(BaseModel):
    mnemonic_length: int = Field(ge=1, le=48)
    known_word_count: int = Field(ge=0, le=48)
    unknown_word_count: Optional[int] = Field(default=None, ge=0, le=48)
    known_positions: List[int] = Field(default_factory=list)
    known_address_available: bool = False
    passphrase_known: bool = False


class PartialMnemonicEstimate(BaseModel):
    raw_word_combination_count: int
    checksum_reduced_estimate: int
    effective_candidate_estimate: int
    feasibility_class: FeasibilityClass
    estimate: EntropyEstimate


class BrainwalletRiskResult(BaseModel):
    risk: str
    confidence: float
    reasoning: List[str]


class SourceAuditRequest(BaseModel):
    source: str = Field(min_length=1, max_length=200_000)
    filename: str = "snippet.py"


class SourceAuditFinding(BaseModel):
    file: str
    line: int
    generator_function: Optional[str] = None
    entropy_source: EntropySource
    risk: str
    evidence: str
    recommendation: str
