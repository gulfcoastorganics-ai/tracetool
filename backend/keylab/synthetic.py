"""Finite, internally generated sequential-search experiments."""

import random
import time
from typing import Optional

from .crypto import SECP256K1_ORDER, coincurve_material
from .models import SyntheticSearchRequest, SyntheticSearchResult


def run_synthetic(request: SyntheticSearchRequest, cancel_event=None) -> SyntheticSearchResult:
    start = 1
    end = start + request.range_size - 1
    position = request.target_position if request.target_position is not None else random.randrange(request.range_size)
    if not 0 <= position < request.range_size:
        raise ValueError("target_position must be inside the requested range")
    secret = start + position
    if secret >= SECP256K1_ORDER:
        raise ValueError("synthetic range exceeds secp256k1 scalar range")
    target = coincurve_material(secret).p2pkh_address
    started = time.perf_counter()
    checked = 0
    recovered = None
    for candidate in range(start, end + 1):
        if cancel_event is not None and cancel_event.is_set():
            return SyntheticSearchResult(status="cancelled", start=start, end=end, target_address=target, range_size=request.range_size, candidates_checked=checked, elapsed_seconds=time.perf_counter() - started, candidates_per_second=checked / max(time.perf_counter() - started, 1e-9), target_position=position, verification=False)
        checked += 1
        if coincurve_material(candidate).p2pkh_address == target:
            recovered = candidate
            break
    elapsed = max(time.perf_counter() - started, 1e-9)
    return SyntheticSearchResult(status="recovered" if recovered is not None else "failed", start=start, end=end, target_address=target, range_size=request.range_size, candidates_checked=checked, elapsed_seconds=elapsed, candidates_per_second=checked / elapsed, target_position=position, verification=recovered == secret, secret_redacted=True)
