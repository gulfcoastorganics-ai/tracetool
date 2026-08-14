"""Bounded local vanity generation. This module never performs network calls."""

import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .crypto import SECP256K1_ORDER, coincurve_material
from .models import VanityRequest, VanityResult


def pattern_matches(value: str, pattern: str, case_sensitive: bool = False, wildcard: bool = False) -> bool:
    if not case_sensitive:
        value, pattern = value.lower(), pattern.lower()
    if not wildcard:
        return value.startswith(pattern)
    # ? matches one character; * matches any suffix. Restrict matching to a
    # prefix pattern so generation remains predictable.
    regex = "^" + "".join("." if c == "?" else ".*" if c == "*" else __import__("re").escape(c) for c in pattern)
    return bool(__import__("re").match(regex, value))


def estimated_difficulty(pattern: str, case_sensitive: bool) -> float:
    alphabet = 58 if pattern.startswith("1") else 32
    if not case_sensitive:
        alphabet = max(2, alphabet // 2)
    return float(alphabet ** max(1, len(pattern) - (1 if pattern.startswith(("1", "3", "b")) else 0)))


def generate_vanity(request: VanityRequest, cancel_event: Optional[threading.Event] = None) -> VanityResult:
    started = time.perf_counter()
    cancel_event = cancel_event or threading.Event()
    candidates = 0
    found = None
    # Thread workers are intentionally long-lived. coincurve releases the GIL
    # during libsecp256k1 work, while each worker owns its counter.
    def worker(worker_id: int):
        nonlocal candidates, found
        scalar = (int.from_bytes(__import__("os").urandom(32), "big") % (SECP256K1_ORDER - 1)) + 1
        local = 0
        while not cancel_event.is_set() and time.perf_counter() - started < request.max_runtime_seconds:
            material = coincurve_material(scalar)
            address = material.p2pkh_address if request.address_type == "p2pkh" else material.p2wpkh_address
            local += 1
            if pattern_matches(address, request.pattern, request.case_sensitive, request.wildcard):
                found = (material, address)
                cancel_event.set()
                break
            scalar = (scalar % (SECP256K1_ORDER - 1)) + 1
        with threading.Lock():
            candidates += local
    with ThreadPoolExecutor(max_workers=request.worker_count, thread_name_prefix="keylab-vanity") as pool:
        futures = [pool.submit(worker, index) for index in range(request.worker_count)]
        for future in as_completed(futures):
            future.result()
            if found:
                break
    elapsed = max(time.perf_counter() - started, 1e-9)
    rate = candidates / elapsed
    status = "found" if found else "cancelled" if cancel_event.is_set() else "completed"
    material, address = found if found else (None, None)
    return VanityResult(
        status=status, address=address,
        public_key=material.public_key_hex if material else None,
        private_key=material.private_key_hex if material else None,
        address_type=request.address_type, pattern=request.pattern,
        candidates_tested=candidates, current_rate=rate, average_rate=rate,
        elapsed_seconds=elapsed, estimated_difficulty=estimated_difficulty(request.pattern, request.case_sensitive),
        estimated_time_remaining=None, worker_count=request.worker_count,
        private_key_redacted=False,
    )
