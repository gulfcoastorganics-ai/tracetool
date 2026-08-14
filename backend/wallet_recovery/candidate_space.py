"""Candidate-space summaries used to gate recovery execution."""

from math import log2

from .feasibility import checksum_bits_for_words
from .models import CandidateSpaceResult, RecoveryClassification, WalletEvidence


def estimate_candidate_space(*, mnemonic_length=None, unknown_words=0, profile_count=1, addresses_per_profile=0, address_evidence=False, known_passphrase=False, weak_effective_bits=None, budget=None, seed_candidates=None):
    if weak_effective_bits is not None:
        before = after = 1 << min(int(weak_effective_bits), 64)
        classification = RecoveryClassification.KNOWN_WEAK_GENERATOR_RECOVERY
        explanation = "Entropy/provenance evidence bounds the generator state before candidate generation."
    elif mnemonic_length and unknown_words:
        before = 2048 ** unknown_words
        after = max(1, before // (1 << checksum_bits_for_words(mnemonic_length)))
        classification = RecoveryClassification.CHECKSUM_CONSTRAINED_RECOVERY if after <= (1 << 20) and address_evidence else RecoveryClassification.COMPUTATIONALLY_INFEASIBLE
        explanation = "BIP39 checksum filtering is applied before any derivation attempt."
    elif mnemonic_length:
        before = after = 1
        classification = RecoveryClassification.EXACT_RECOVERY
        explanation = "Complete mnemonic supplied; only configuration/path alternatives remain."
    else:
        before = after = None
        classification = RecoveryClassification.COMPUTATIONALLY_INFEASIBLE
        explanation = "No justified reduction from the normal secret search space exists."
    estimated = (profile_count * addresses_per_profile * max(1, after or 1))
    if seed_candidates is not None:
        estimated = max(1, int(seed_candidates)) * max(1, profile_count) * max(1, addresses_per_profile)
    feasible = classification in {RecoveryClassification.EXACT_RECOVERY, RecoveryClassification.CHECKSUM_CONSTRAINED_RECOVERY, RecoveryClassification.DERIVATION_PATH_RECOVERY, RecoveryClassification.BIP39_PASSPHRASE_RECOVERY, RecoveryClassification.WALLET_ARTIFACT_RECOVERY, RecoveryClassification.KNOWN_WEAK_GENERATOR_RECOVERY}
    budget_data = budget.model_dump(mode="json") if hasattr(budget, "model_dump") else budget
    runtime = round(estimated / 1000, 2) if budget_data and estimated else None
    return CandidateSpaceResult(classification=classification, candidate_space_before_constraints=before, candidate_space_after_checksum=after, derivation_profiles=profile_count, addresses_per_profile=addresses_per_profile, estimated_derivations=estimated, strongest_verification_evidence="KNOWN_ADDRESS" if address_evidence else None, feasible=feasible, explanation=explanation, estimated_runtime_seconds=runtime, budget=budget_data)
