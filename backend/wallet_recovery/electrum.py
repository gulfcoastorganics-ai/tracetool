"""Electrum seed-version detection before BIP39 validation."""

import hashlib
import hmac
import unicodedata


PREFIXES = {
    "01": ("standard", False),
    "100": ("segwit", False),
    "101": ("standard", True),
    "102": ("segwit", True),
}


def detect_electrum_seed(seed: str):
    normalized = unicodedata.normalize("NFKD", seed).strip()
    digest = hmac.new(b"Seed version", normalized.encode("utf-8"), hashlib.sha512).hexdigest()
    prefix = next((key for key in sorted(PREFIXES, key=len, reverse=True) if digest.startswith(key)), None)
    if prefix is None:
        return {"recognized": False, "normalized": True}
    wallet_type, two_factor = PREFIXES[prefix]
    return {"recognized": True, "seed_version_prefix": prefix, "wallet_type": wallet_type, "two_factor": two_factor, "normalized": True, "hmac_checked": True}
