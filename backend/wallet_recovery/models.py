"""Models for evidence-driven wallet recovery assessment."""

from datetime import date
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class RecoveryClassification(str, Enum):
    EXACT_RECOVERY = "EXACT_RECOVERY"
    CHECKSUM_CONSTRAINED_RECOVERY = "CHECKSUM_CONSTRAINED_RECOVERY"
    DERIVATION_PATH_RECOVERY = "DERIVATION_PATH_RECOVERY"
    BIP39_PASSPHRASE_RECOVERY = "BIP39_PASSPHRASE_RECOVERY"
    WALLET_ARTIFACT_RECOVERY = "WALLET_ARTIFACT_RECOVERY"
    KNOWN_WEAK_GENERATOR_RECOVERY = "KNOWN_WEAK_GENERATOR_RECOVERY"
    RECOVERABLE_CONFIGURATION = "RECOVERABLE_CONFIGURATION"
    RECOVERABLE_PARTIAL_MNEMONIC = "RECOVERABLE_PARTIAL_MNEMONIC"
    RECOVERABLE_DERIVATION_PATH = "RECOVERABLE_DERIVATION_PATH"
    RECOVERABLE_KNOWN_WEAK_GENERATOR = "RECOVERABLE_KNOWN_WEAK_GENERATOR"
    CONDITIONALLY_FEASIBLE = "CONDITIONALLY_FEASIBLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    COMPUTATIONALLY_INFEASIBLE = "COMPUTATIONALLY_INFEASIBLE"


class RecoveryStatus(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    BLOCKED = "BLOCKED"


class RecoveryServiceResult(str, Enum):
    SUFFICIENT_PRIVATE_EVIDENCE = "SUFFICIENT_PRIVATE_EVIDENCE"
    RECOVERY_FEASIBLE = "RECOVERY_FEASIBLE"
    VALID_RECOVERY_CANDIDATE = "VALID_RECOVERY_CANDIDATE"
    PUBLIC_IDENTIFIER_MATCH = "PUBLIC_IDENTIFIER_MATCH"
    UNIQUE_PUBLIC_MATCH = "UNIQUE_PUBLIC_MATCH"
    RECOVERY_CONFIRMED = "RECOVERY_CONFIRMED"
    INSUFFICIENT_PRIVATE_EVIDENCE = "INSUFFICIENT_PRIVATE_EVIDENCE"
    CRYPTOGRAPHICALLY_INFEASIBLE = "CRYPTOGRAPHICALLY_INFEASIBLE"
    PRIVATE_EVIDENCE_SUFFICIENT = "PRIVATE_EVIDENCE_SUFFICIENT"
    PUBLIC_MATCH_PENDING = "PUBLIC_MATCH_PENDING"


class RecoveryTermination(str, Enum):
    EXACT_MATCH = "EXACT_MATCH"
    UNIQUE_PUBLIC_MATCH = "UNIQUE_PUBLIC_MATCH"
    MULTIPLE_PLAUSIBLE_CANDIDATES = "MULTIPLE_PLAUSIBLE_CANDIDATES"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    NO_CHECKSUM_VALID_CANDIDATES = "NO_CHECKSUM_VALID_CANDIDATES"
    PUBLIC_CONSTRAINT_MISMATCH = "PUBLIC_CONSTRAINT_MISMATCH"
    PASSPHRASE_SPACE_TOO_LARGE = "PASSPHRASE_SPACE_TOO_LARGE"
    CHAIN_EVIDENCE_UNAVAILABLE = "CHAIN_EVIDENCE_UNAVAILABLE"
    COMPUTATIONALLY_INFEASIBLE = "COMPUTATIONALLY_INFEASIBLE"
    LOCAL_MATCH_REQUIRES_HISTORY_DISAMBIGUATION = "LOCAL_MATCH_REQUIRES_HISTORY_DISAMBIGUATION"


class RecoveryEvidenceType(str, Enum):
    MASTER_FINGERPRINT_MATCH = "MASTER_FINGERPRINT_MATCH"
    ACCOUNT_XPUB_MATCH = "ACCOUNT_XPUB_MATCH"
    DESCRIPTOR_MATCH = "DESCRIPTOR_MATCH"
    MULTISIG_POLICY_MATCH = "MULTISIG_POLICY_MATCH"
    CHILD_PUBKEY_MATCH = "CHILD_PUBKEY_MATCH"
    ADDRESS_MATCH = "ADDRESS_MATCH"
    HISTORY_MATCH = "HISTORY_MATCH"


class EvidenceItem(BaseModel):
    kind: str
    description: str
    confidence: float = Field(default=0.5, ge=0, le=1)
    source: str = "owner"


class WalletEvidence(BaseModel):
    known_addresses: List[str] = Field(default_factory=list, max_length=32)
    network: Optional[str] = None
    wallet_application: Optional[str] = None
    approximate_creation_date: Optional[date] = None
    known_derivation_path: Optional[str] = None
    wallet_type: Optional[str] = None
    complete_mnemonic: Optional[str] = Field(default=None, min_length=1, max_length=512)
    partial_mnemonic: Optional[str] = Field(default=None, min_length=1, max_length=512)
    known_word_positions: List[int] = Field(default_factory=list, max_length=48)
    mnemonic_word_constraints: Dict[int, List[str]] = Field(default_factory=dict, max_length=48)
    mnemonic_prefixes: Dict[int, str] = Field(default_factory=dict, max_length=48)
    allow_adjacent_word_swaps: bool = False
    max_word_edit_distance: int = Field(default=0, ge=0, le=2)
    passphrase_hints: List[str] = Field(default_factory=list, max_length=16)
    passphrase_components: List[str] = Field(default_factory=list, max_length=16)
    passphrase_years: List[int] = Field(default_factory=list, max_length=16)
    passphrase_suffixes: List[str] = Field(default_factory=list, max_length=16)
    passphrase_separators: List[str] = Field(default_factory=list, max_length=16)
    passphrase_capitalization_variants: bool = False
    passphrase_whitespace_variants: bool = False
    passphrase_keyboard_variants: bool = False
    passphrase_normalization_variants: bool = False
    passphrase_known: bool = False
    private_key_available: bool = False
    generator_source: Optional[str] = Field(default=None, max_length=300_000)
    entropy_assurance_report: Optional[Dict[str, Any]] = None
    extended_public_key: Optional[str] = Field(default=None, max_length=256)
    master_fingerprint: Optional[str] = Field(default=None, max_length=16)
    extended_private_key: Optional[str] = Field(default=None, max_length=256)
    output_descriptor: Optional[str] = Field(default=None, max_length=2048)
    transaction_ids: List[str] = Field(default_factory=list, max_length=32)
    transaction_dates: List[date] = Field(default_factory=list, max_length=32)
    approximate_balance: Optional[float] = Field(default=None, ge=0)
    asset_symbol: Optional[str] = Field(default=None, max_length=32)
    ens_or_name: Optional[str] = Field(default=None, max_length=256)
    exchange_withdrawal_address: Optional[str] = Field(default=None, max_length=128)
    wallet_era: Optional[str] = Field(default=None, max_length=32)
    watch_only_export: Optional[str] = Field(default=None, max_length=100_000)
    wallet_artifact_path: Optional[str] = Field(default=None, max_length=4096)
    wallet_artifact_type: Optional[str] = None
    chain_history_verification: bool = False
    chain_history_provider: Optional[str] = Field(default=None, max_length=64)

    @field_validator("known_addresses")
    @classmethod
    def normalize_addresses(cls, values):
        return [value.strip() for value in values if value and value.strip()]


class RecoveryAnalysisRequest(BaseModel):
    evidence: WalletEvidence = Field(default_factory=WalletEvidence)
    requested_account_start: int = Field(default=0, ge=0, le=10)
    requested_account_count: int = Field(default=1, ge=1, le=5)
    requested_index_start: int = Field(default=0, ge=0, le=100)
    requested_index_count: int = Field(default=5, ge=1, le=20)
    budget: Optional["RecoveryBudget"] = None


class DerivationExploreRequest(BaseModel):
    session_token: str = Field(min_length=20, max_length=128)
    networks: List[str] = Field(default_factory=lambda: ["bitcoin", "ethereum", "solana"], max_length=3)
    account_start: int = Field(default=0, ge=0, le=5)
    account_count: int = Field(default=1, ge=1, le=3)
    index_start: int = Field(default=0, ge=0, le=100)
    index_count: int = Field(default=5, ge=1, le=20)
    passphrase: Optional[str] = Field(default=None, max_length=256)
    profile_ids: List[str] = Field(default_factory=list, max_length=8)
    budget: Optional["RecoveryBudget"] = None
    resume_candidate_offset: int = Field(default=0, ge=0, le=100_000)


class RecoveryBudget(BaseModel):
    """Work budget; counts expensive seed/KDF work separately from child derivation."""
    max_seed_candidates: int = Field(default=8, ge=1, le=100_000)
    max_pbkdf2_operations: int = Field(default=8, ge=1, le=100_000)
    max_paths_per_seed: int = Field(default=24, ge=1, le=10_000)
    max_child_derivations: int = Field(default=180, ge=1, le=100_000)
    max_chain_queries: int = Field(default=0, ge=0, le=10_000)
    max_runtime_seconds: float = Field(default=30.0, gt=0, le=3600)
    max_memory_mb: int = Field(default=256, ge=16, le=4096)
    max_kdf_work: int = Field(default=16_384, ge=1, le=10_000_000)


class AddressVerificationRequest(BaseModel):
    session_token: str = Field(min_length=20, max_length=128)
    address: str = Field(min_length=4, max_length=128)
    network: str
    derivation_path: Optional[str] = None
    passphrase: Optional[str] = Field(default=None, max_length=256)


class MnemonicAnalysisRequest(BaseModel):
    mnemonic_length: int = Field(default=24, ge=1, le=48)
    partial_mnemonic: Optional[str] = Field(default=None, max_length=512)
    known_word_positions: List[int] = Field(default_factory=list, max_length=48)
    known_word_count: Optional[int] = Field(default=None, ge=0, le=48)
    expected_address_available: bool = False
    expected_address: Optional[str] = None


class GeneratorAnalysisRequest(BaseModel):
    generator_source: Optional[str] = Field(default=None, max_length=300_000)
    entropy_assurance_report: Optional[Dict[str, Any]] = None
    known_wallet_application: Optional[str] = None
    known_creation_date: Optional[date] = None
    known_address_available: bool = False


class RecoveryPlanRequest(RecoveryAnalysisRequest):
    pass


class RecoverySessionRequest(BaseModel):
    evidence: WalletEvidence = Field(default_factory=WalletEvidence)
    ttl_seconds: int = Field(default=900, ge=60, le=3600)


class RecoverySessionResponse(BaseModel):
    session_token: str
    expires_in_seconds: int
    sensitive_values_in_memory_only: bool = True


class FeasibilityResult(BaseModel):
    classification: RecoveryClassification
    candidate_count: Optional[int] = None
    effective_bits: Optional[float] = None
    explanation: str
    recommended_action: str
    expensive_work_allowed: bool = False


class RecoveryAnalysisResult(BaseModel):
    classification: RecoveryClassification
    feasibility: FeasibilityResult
    evidence_summary: List[EvidenceItem] = Field(default_factory=list)
    diagnosis: str
    recommended_path: str
    derivation_paths_to_try: List[str] = Field(default_factory=list)
    sensitive_values_redacted: bool = True
    wallet_fingerprint: Optional[Dict[str, Any]] = None
    matched_profiles: List[Dict[str, Any]] = Field(default_factory=list)
    candidate_space: Optional[Dict[str, Any]] = None
    path_hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    backup_format: Optional[Dict[str, Any]] = None
    early_wallet_identification: Optional[Dict[str, Any]] = None
    service_result: RecoveryServiceResult = RecoveryServiceResult.INSUFFICIENT_PRIVATE_EVIDENCE
    ownership_evidence: str = "OWNER_EVIDENCE_PRESENT"
    private_evidence: str = "INSUFFICIENT"
    public_match_status: str = "PENDING"


class DerivedIdentifier(BaseModel):
    network: str
    path: str
    address: str
    matched: bool = False


class DerivationResult(BaseModel):
    status: RecoveryStatus
    identifiers: List[DerivedIdentifier] = Field(default_factory=list)
    matches: List[DerivedIdentifier] = Field(default_factory=list)
    derivations_attempted: int
    sensitive_values_redacted: bool = True
    checkpoint: Optional[Dict[str, Any]] = None
    termination: Optional[RecoveryTermination] = None
    preflight: Optional[Dict[str, Any]] = None
    candidate_provenance: List[Dict[str, Any]] = Field(default_factory=list)
    service_result: RecoveryServiceResult = RecoveryServiceResult.VALID_RECOVERY_CANDIDATE
    ownership_evidence: str = "OWNER_EVIDENCE_PRESENT"
    private_evidence: str = "SUFFICIENT"
    public_match_status: str = "PENDING"


class AddressVerificationResult(BaseModel):
    status: RecoveryStatus
    network: str
    address: str
    derivation_path: Optional[str] = None
    recovery_basis: str = "owner-supplied evidence"
    service_result: RecoveryServiceResult = RecoveryServiceResult.VALID_RECOVERY_CANDIDATE
    public_match_status: str = "PENDING"
    secret: str = "REDACTED"
    export_requires_explicit_local_reveal: bool = True


class MnemonicAnalysisResult(BaseModel):
    mnemonic_length: int
    known_word_count: int
    unknown_word_count: int
    raw_word_combination_count: int
    checksum_bits: int
    checksum_reduced_candidate_count: int
    feasibility: FeasibilityResult
    checksum_is_not_entropy: bool = True


class GeneratorAnalysisResult(BaseModel):
    classification: RecoveryClassification
    effective_bits: Optional[float]
    candidate_space_display: str
    provenance_evidence: List[str] = Field(default_factory=list)
    recommendation: str


class RecoveryPlanResult(BaseModel):
    classification: RecoveryClassification
    ordered_steps: List[str]
    blocked_operations: List[str]
    requires_owner_verification: bool = True
    sensitive_values_redacted: bool = True


class RecoveryReport(BaseModel):
    classification: RecoveryClassification
    diagnosis: str
    recovery_basis: str
    verification_status: RecoveryStatus
    network: Optional[str] = None
    matched_address: Optional[str] = None
    derivation_path: Optional[str] = None
    secret: str = "REDACTED"
    created_at: str


class WalletFingerprint(BaseModel):
    networks: List[str] = Field(default_factory=list)
    address_types: List[str] = Field(default_factory=list)
    wallet_applications: List[str] = Field(default_factory=list)
    likely_profiles: List[str] = Field(default_factory=list)
    known_address_count: int = 0
    extended_key_type: Optional[str] = None
    master_fingerprint: Optional[str] = None
    descriptor_present: bool = False
    transaction_evidence_count: int = 0
    creation_year: Optional[int] = None
    account_hint: Optional[int] = None
    branch_hint: Optional[str] = None
    evidence_strength: float = 0


class WalletProfile(BaseModel):
    id: str
    name: str
    applications: List[str]
    networks: List[str]
    purposes: List[int]
    coin_type: int
    change_branches: List[int]
    address_type: str
    default_gap_limit: int = 20
    historical_quirks: List[str] = Field(default_factory=list)


class RecoveryConstraintSet(BaseModel):
    mnemonic_length: Optional[int] = None
    known_positions: List[int] = Field(default_factory=list)
    restricted_positions: Dict[int, List[str]] = Field(default_factory=dict)
    uncertain_positions: List[int] = Field(default_factory=list)
    passphrase_candidates: List[str] = Field(default_factory=list)
    capitalization_variants: bool = False
    whitespace_variants: bool = False
    normalization_variants: bool = False
    account_start: int = 0
    account_count: int = 1
    branch_values: List[int] = Field(default_factory=lambda: [0])
    index_start: int = 0
    index_count: int = 20
    word_constraints: Dict[int, List[str]] = Field(default_factory=dict)
    allowed_transpositions: bool = False
    allow_adjacent_swaps: bool = False
    prefix_completion: bool = False
    max_edit_distance: int = Field(default=0, ge=0, le=2)
    passphrase_grammar: Dict[str, Any] = Field(default_factory=dict)


class CandidateSpaceResult(BaseModel):
    classification: RecoveryClassification
    candidate_space_before_constraints: Optional[int] = None
    candidate_space_after_checksum: Optional[int] = None
    derivation_profiles: int = 0
    addresses_per_profile: int = 0
    estimated_derivations: int = 0
    strongest_verification_evidence: Optional[str] = None
    feasible: bool = False
    explanation: str
    estimated_runtime_seconds: Optional[float] = None
    budget: Optional[Dict[str, Any]] = None


class GapScanRequest(DerivationExploreRequest):
    profile_ids: List[str] = Field(default_factory=list, max_length=8)
    gap_limit: int = Field(default=20, ge=1, le=50)
    scan_change: bool = True


class ExtendedKeyAnalysisResult(BaseModel):
    present: bool
    key_type: Optional[str] = None
    network: Optional[str] = None
    address_type: Optional[str] = None
    checksum_valid: Optional[bool] = None
    public_verification_only: bool = True
    fingerprint: Optional[str] = None


class ArtifactAnalysisResult(BaseModel):
    artifact_type: Optional[str] = None
    detected: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
    secret_decryption_attempted: bool = False
    recommendation: str


class ArtifactInspectRequest(BaseModel):
    artifact: Dict[str, Any] | str = Field(description="Inline owner-supplied artifact JSON or local path")


class ArtifactPasswordRequest(ArtifactInspectRequest):
    password: str = Field(min_length=1, max_length=1024)


class ExtendedKeyGapRequest(BaseModel):
    extended_public_key: str = Field(min_length=20, max_length=256)
    network: str = "bitcoin"
    gap_limit: int = Field(default=20, ge=1, le=50)
    max_index: int = Field(default=1000, ge=1, le=5000)


class BackupFormatRequest(BaseModel):
    backup: str | List[str] = Field(min_length=1)


class Slip39RecoveryRequest(BaseModel):
    shares: List[str] = Field(min_length=1, max_length=16)
    passphrase: str = Field(default="", max_length=256)


class PolicyInspectRequest(BaseModel):
    policy: Dict[str, Any] | str


class BSMSInspectRequest(BaseModel):
    artifact: Dict[str, Any] | str
