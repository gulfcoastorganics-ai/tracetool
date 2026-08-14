"""Entropy-preservation helpers used by audits and comparisons."""

from .pipeline import analyze_pipeline


def preserved_entropy(*, source_bits: int | None, consumed_bits: int | None = None, discarded_bits: int = 0, final_output_bits: int | None = None, transformations=None):
    return analyze_pipeline(source_bits=source_bits, consumed_bits=consumed_bits or source_bits, discarded_bits=discarded_bits, final_output_bits=final_output_bits, transformations=transformations)
