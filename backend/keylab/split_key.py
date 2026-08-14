"""Capability gate for split-key vanity generation.

The installed bindings do not provide a reviewed, ergonomic public-key
addition protocol with sufficient test coverage for a production feature.
This endpoint is deliberately disabled rather than shipping uncertain
cryptography.
"""

from .models import SplitKeyRequest, SplitKeyResult


def split_key(request: SplitKeyRequest) -> SplitKeyResult:
    return SplitKeyResult(enabled=False, status="disabled", message="Split-key vanity generation is disabled until a reviewed public-key contribution protocol is available.")
