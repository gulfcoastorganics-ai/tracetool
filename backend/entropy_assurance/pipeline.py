"""Small, explicit source-to-sink entropy pipeline representation."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EntropyPipeline:
    source_width: Optional[int] = None
    consumed_width: Optional[int] = None
    discarded_bits: int = 0
    final_output_width: Optional[int] = None
    transformations: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def maximum_effective_bits(self) -> Optional[int]:
        candidates = [value for value in (self.source_width, self.consumed_width) if value is not None]
        if self.discarded_bits:
            candidates.append(max(0, (self.source_width or self.consumed_width or 0) - self.discarded_bits))
        return min(candidates) if candidates else None

    def add_source(self, bits: int, label: str):
        self.source_width = bits
        self.consumed_width = bits
        self.transformations.append(label)
        return self

    def retain(self, bits: int, label: str):
        before = self.consumed_width or self.source_width or bits
        self.discarded_bits += max(0, before - bits)
        self.consumed_width = bits
        self.transformations.append(label)
        return self

    def expand(self, output_bits: int, label: str):
        self.final_output_width = output_bits
        self.transformations.append(label)
        self.notes.append("Output width expansion does not recreate discarded entropy.")
        return self


def analyze_pipeline(*, source_bits: Optional[int], consumed_bits: Optional[int], discarded_bits: int = 0, final_output_bits: Optional[int] = None, transformations=None):
    pipeline = EntropyPipeline(source_width=source_bits, consumed_width=consumed_bits, discarded_bits=discarded_bits, final_output_width=final_output_bits, transformations=list(transformations or []))
    return {
        "source_width": pipeline.source_width,
        "consumed_width": pipeline.consumed_width,
        "discarded_bits": pipeline.discarded_bits,
        "final_output_width": pipeline.final_output_width,
        "maximum_effective_bits": pipeline.maximum_effective_bits,
        "transformations": pipeline.transformations,
        "notes": pipeline.notes,
    }
