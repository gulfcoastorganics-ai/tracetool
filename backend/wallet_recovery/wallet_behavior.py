"""Wallet behavior fingerprints used to narrow hypotheses before KDF work."""


def build_behavior_fingerprint(*, wallet_application=None, wallet_version=None, creation_year=None, wallet_type=None, address_types=None, gap_limit=None, change_branches=None, account_number=None, descriptor=None, seed_format=None):
    app = (wallet_application or "").lower()
    if gap_limit is None:
        gap_limit = 20 if "electrum" not in app else 20
    if change_branches is None:
        change_branches = [0, 1] if wallet_type in {"bitcoin", "multisig"} else [0]
    return {"wallet_application": wallet_application, "wallet_version": wallet_version, "creation_year": creation_year, "wallet_type": wallet_type, "address_types": list(address_types or []), "historical_gap_limit": gap_limit, "change_branches": list(change_branches), "account_number": account_number, "descriptor_policy": descriptor, "seed_format": seed_format, "electrum_semantics": seed_format == "ELECTRUM_SEED_VERSION", "confidence": 0.8 if wallet_application or descriptor else 0.3}
