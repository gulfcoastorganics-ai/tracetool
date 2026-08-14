"""Checksum-aware partial mnemonic analysis without blind candidate generation."""

from .feasibility import partial_mnemonic_feasibility


def analyze_partial_mnemonic(*, mnemonic_length: int, known_word_count: int | None = None, unknown_word_count: int | None = None, known_positions=None, address_available=False):
    positions = known_positions or []
    unknown = unknown_word_count if unknown_word_count is not None else max(0, mnemonic_length - (known_word_count or len(positions)))
    feasibility, raw, checksum, reduced = partial_mnemonic_feasibility(mnemonic_length=mnemonic_length, unknown_word_count=unknown, address_available=address_available)
    return {"mnemonic_length": mnemonic_length, "known_word_count": mnemonic_length - unknown, "unknown_word_count": unknown, "raw_word_combination_count": raw, "checksum_bits": checksum, "checksum_reduced_candidate_count": reduced, "feasibility": feasibility, "checksum_is_not_entropy": True}
