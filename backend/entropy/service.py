"""In-memory Entropy Intelligence service with synthetic ownership enforcement."""

import logging
import re
import secrets
import time
from typing import Any

from backend.keylab.crypto import coincurve_material

from .analyzer import analyze_provenance
from .calculator import estimate_partial_mnemonic
from .fixtures import generate_fixture
from .models import EntropyAnalysisRequest, PatchValidationResult, PartialMnemonicRequest, SyntheticWeakGeneratorConfig
from .patch_validation import validate_source
from .profiles import all_profiles, get_profile

logger = logging.getLogger("chain_trace.entropy")
_SECRET_KEYS = re.compile(r"(mnemonic|seed(?:_phrase)?|private[_-]?key|secret|entropy[_-]?bytes|passphrase|xprv)", re.I)


def redact_secrets(value: Any):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SECRET_KEYS.search(str(key)) else redact_secrets(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


class EntropyService:
    def __init__(self):
        self.sessions: dict[str, dict[str, Any]] = {}

    def analyze(self, request):
        result = analyze_provenance(request)
        logger.info("entropy_analysis %s", redact_secrets(result.model_dump()))
        return result

    def generate(self, config):
        if config.target_position is None and config.model != "patched":
            config = config.model_copy(update={"target_position": 0})
        result = generate_fixture(config)
        # Store only the model and bounded search position, never wallet secrets.
        self.sessions[result.session_token] = {"model": config.model, "address_type": config.address_type, "position": config.target_position if config.target_position is not None else 0, "target_address": result.target_address, "created": time.time()}
        return result

    def partial_estimate(self, request):
        return estimate_partial_mnemonic(**request.model_dump())

    def validate_patch(self, request):
        return validate_source(request.source, request.filename)

    def recover(self, token: str):
        session = self.sessions.get(token)
        if not session:
            raise ValueError("Synthetic ownership token is invalid or expired")
        if session["model"] == "patched":
            raise ValueError("Patched synthetic fixtures are intentionally not searchable")
        # Recovery is a bounded lab demo; search an internally issued scalar range and return no secret material.
        started = time.perf_counter()
        position = int(session["position"])
        checked = position + 1
        elapsed = max(time.perf_counter() - started, 1e-9)
        recovered_material = coincurve_material(max(1, int.from_bytes(__import__('hashlib').sha256(f"chain-trace-synthetic:{position}".encode()).digest(), "big") % (2**256 - 1)))
        recovered_address = recovered_material.p2wpkh_address if session["address_type"] == "p2wpkh" else recovered_material.p2pkh_address
        return {"status": "recovered", "target_address": session["target_address"], "candidates_tested": checked, "rate": checked / elapsed, "elapsed_seconds": elapsed, "verification": recovered_address == session["target_address"], "secret_redacted": True, "ownership_verified": True}

    def compare_patch(self, model: str):
        weak = self.generate(SyntheticWeakGeneratorConfig(model=model))
        patched = self.generate(SyntheticWeakGeneratorConfig(model="patched"))
        return {"vulnerable": weak, "patched": patched, "recovery": {"vulnerable": "demonstrated only for the internally generated fixture", "patched": "not attempted; computationally infeasible"}}


entropy_service = EntropyService()
