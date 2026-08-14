"""Conservative effective-entropy and search-space calculations."""

from math import ceil, log2
from typing import Iterable, Optional

from .models import EntropyClassification, EntropyEstimate, FeasibilityClass, KnownConstraint

# These are policy thresholds, not runtime guarantees.
TRIVIAL_LAB_MAX = 1 << 16
SMALL_BOUNDED_MAX = 1 << 24
PRACTICAL_MAX = 1 << 32
EXPENSIVE_MAX = 1 << 48


def _space(bits: float) -> int:
    if bits <= 0:
        return 1
    if bits >= 4096:
        return 1 << 4096
    return 1 << int(ceil(bits))


def display_space(bits: Optional[float], count: Optional[int] = None) -> str:
    if count is not None and count < 10_000_000:
        return f"{count:,} candidates"
    if bits is None:
        return "unknown"
    return f"2^{bits:.1f} candidates" if bits % 1 else f"2^{int(bits)} candidates"


def feasibility_for(bits: Optional[float], count: Optional[int] = None) -> FeasibilityClass:
    if bits is None:
        return FeasibilityClass.UNKNOWN
    magnitude = count if count is not None else (float("inf") if bits > 1024 else 2 ** bits)
    if magnitude <= TRIVIAL_LAB_MAX:
        return FeasibilityClass.TRIVIAL_LAB
    if magnitude <= SMALL_BOUNDED_MAX:
        return FeasibilityClass.SMALL_BOUNDED
    if magnitude <= PRACTICAL_MAX:
        return FeasibilityClass.PRACTICAL_WITH_CONSTRAINTS
    if magnitude <= EXPENSIVE_MAX:
        return FeasibilityClass.EXPENSIVE
    return FeasibilityClass.COMPUTATIONALLY_INFEASIBLE


def estimate_entropy(*, mnemonic_length: Optional[int] = None, nominal_entropy_bits: Optional[float] = None,
                     unknown_mnemonic_words: Optional[int] = None, checksum_bits: Optional[int] = None,
                     generator_state_width_bits: Optional[int] = None,
                     documented_generator_state_reduction: Optional[float] = None,
                     constraints: Iterable[KnownConstraint] = (), confidence: float = 0.25,
                     classification: Optional[EntropyClassification] = None,
                     extra_factors: Iterable[str] = (), candidate_count: Optional[int] = None,
                     measured_rate: Optional[float] = None) -> EntropyEstimate:
    factors = list(extra_factors)
    nominal = nominal_entropy_bits
    checksum = checksum_bits or 0
    if nominal is None and mnemonic_length:
        # BIP39 ENT = 32 * (words / 3) - 32, generalized for the standard lengths.
        nominal = (mnemonic_length * 11) - (mnemonic_length * 11 // 32)
        checksum = mnemonic_length * 11 - int(nominal)
        factors.append(f"BIP39 nominal entropy derived from {mnemonic_length} words")
    effective = nominal
    if unknown_mnemonic_words is not None:
        # Unknown words are 11-bit symbols; checksum is a constraint, not entropy.
        candidate_count = 2048 ** unknown_mnemonic_words
        effective = log2(candidate_count) if candidate_count else 0
        if checksum:
            candidate_count = max(1, candidate_count // (1 << checksum))
            effective = log2(candidate_count)
        factors.append(f"{unknown_mnemonic_words} unknown mnemonic words constrain the search")
    reductions = sum(item.entropy_reduction_bits * item.confidence for item in constraints)
    if reductions:
        effective = max(0, (effective or 0) - reductions)
        factors.append(f"known constraints reduce estimated entropy by about {reductions:.1f} bits")
    if documented_generator_state_reduction:
        effective = max(0, (effective or 0) - documented_generator_state_reduction)
        factors.append(f"documented generator reduction: {documented_generator_state_reduction:.1f} bits")
    if generator_state_width_bits is not None:
        effective = min(effective if effective is not None else generator_state_width_bits, generator_state_width_bits)
        factors.append(f"generator state bounds effective entropy at {generator_state_width_bits} bits")
    if effective is not None and candidate_count is None:
        candidate_count = _space(effective)
    if effective is not None and classification is None:
        classification = EntropyClassification.INFEASIBLE_SEARCH_SPACE if effective >= 80 else EntropyClassification.REDUCED_ENTROPY
    classification = classification or EntropyClassification.INSUFFICIENT_EVIDENCE
    feasibility = feasibility_for(effective, candidate_count)
    seconds = (candidate_count / measured_rate) if candidate_count and measured_rate else None
    return EntropyEstimate(
        nominal_entropy_bits=nominal, estimated_effective_entropy_bits=effective,
        estimated_candidate_space=candidate_count, candidate_space_display=display_space(effective, candidate_count),
        evidence_confidence=confidence, reasoning_factors=factors,
        classification=classification, feasibility_class=feasibility, checksum_bits=checksum,
        illustrative_rate_candidates_per_second=measured_rate, illustrative_full_space_seconds=seconds,
    )


def estimate_partial_mnemonic(*, mnemonic_length: int, known_word_count: int,
                              unknown_word_count: Optional[int] = None, known_positions=None,
                              known_address_available: bool = False, passphrase_known: bool = False):
    unknown = unknown_word_count if unknown_word_count is not None else max(0, mnemonic_length - known_word_count)
    raw = 2048 ** unknown
    checksum_bits = max(1, (mnemonic_length * 11) - ((mnemonic_length * 11 * 32) // 33)) if mnemonic_length in (12, 15, 18, 21, 24) else 0
    reduced = max(1, raw // (1 << checksum_bits))
    if known_address_available:
        reduced = max(1, reduced // 1)  # An address verifies candidates; it is not independent entropy.
    effective = max(0, log2(reduced))
    estimate = estimate_entropy(nominal_entropy_bits=mnemonic_length * 11 - checksum_bits,
        unknown_mnemonic_words=unknown, checksum_bits=checksum_bits, candidate_count=reduced,
        confidence=0.9, classification=EntropyClassification.PARTIAL_RECOVERY_SCENARIO,
        extra_factors=["checksum is treated as a validity filter, not independent entropy",
                       "known passphrase" if passphrase_known else "passphrase state is not fully known"])
    return {
        "raw_word_combination_count": raw, "checksum_reduced_estimate": reduced,
        "effective_candidate_estimate": reduced, "feasibility_class": feasibility_for(effective, reduced),
        "estimate": estimate,
    }
