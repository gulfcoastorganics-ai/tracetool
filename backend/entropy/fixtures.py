"""Chain-Trace-owned synthetic weak-generator fixtures."""

import hashlib
import secrets
import time
import uuid

from backend.keylab.crypto import coincurve_material

from .calculator import display_space, feasibility_for
from .models import FeasibilityClass, SyntheticWeakGeneratorConfig, SyntheticWeakGeneratorResult


def _scalar(seed: int) -> int:
    digest = hashlib.sha256(f"chain-trace-synthetic:{seed}".encode()).digest()
    return max(1, int.from_bytes(digest, "big") % (2**256 - 1))


def generate_fixture(config: SyntheticWeakGeneratorConfig):
    if config.model == "patched":
        seed = secrets.randbits(256)
        bits = 256
    elif config.model == "timestamp":
        seed = int(time.time()) & 0xFFFF
        bits = 16
    elif config.model == "repeated":
        seed = 7
        bits = 1
    elif config.model == "truncated":
        seed = secrets.randbits(32)
        bits = 32
    else:
        bits = int(config.model)
        seed = secrets.randbits(bits)
    target_position = config.target_position if config.target_position is not None else secrets.randbelow(min(1024, 1 << min(bits, 10)))
    # The bounded lab maps the internally chosen position to the deterministic fixture.
    if config.model != "patched":
        seed = target_position
    secret = _scalar(seed)
    material = coincurve_material(secret)
    target = material.p2wpkh_address if config.address_type == "p2wpkh" else material.p2pkh_address
    space = 1 << min(bits, 256)
    return SyntheticWeakGeneratorResult(session_token=f"ct-lab-{uuid.uuid4().hex}", model=config.model, target_address=target, address_type=config.address_type, nominal_entropy_bits=bits, actual_effective_entropy_bits=bits, candidate_space=space, candidate_space_display=display_space(bits), feasibility_class=feasibility_for(bits), recovery_allowed=config.model != "patched")


def fixture_secret(token: str, config: SyntheticWeakGeneratorConfig):
    # Token ownership is held by service memory; this function only maps a model to a bounded fixture search.
    return _scalar(7 if config.model == "repeated" else (config.target_position or 0))
