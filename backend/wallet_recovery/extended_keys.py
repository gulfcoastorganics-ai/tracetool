"""Extended-key metadata and public-only Bitcoin child derivation."""

from .fingerprint import classify_extended_key
from .models import ExtendedKeyAnalysisResult


def derive_extended_key_addresses(value: str | None, *, branches=(0, 1), index_start=0, index_count=20):
    """Derive public Bitcoin addresses from an owner-supplied xpub-family key.

    bitcoinlib performs checksum/version validation and public child derivation.
    No private key is needed or returned; malformed/unsupported keys yield a
    structured error rather than falling back to secret search.
    """
    kind = classify_extended_key(value)
    if not kind or kind.endswith("prv"):
        return {"present": bool(value), "public_only": False, "addresses": [], "error": "A valid public extended key is required"}
    try:
        # embit is public-only and does not initialize bitcoinlib's global
        # logger/database. This matters in restricted containers and keeps
        # xpub inspection independent of writable home-directory state.
        from embit import bip32, script
        from embit.networks import NETWORKS
        root = bip32.HDKey.from_base58(value)
        network = NETWORKS["test"] if kind in {"tpub", "upub", "vpub"} else NETWORKS["main"]
        addresses = []
        for branch in list(branches)[:2]:
            for index in range(index_start, index_start + min(index_count, 100)):
                child = root.child(int(branch)).child(int(index))
                addresses.append({"path": f"m/{int(branch)}/{index}", "address": script.p2pkh(child.get_public_key()).address(network)})
        return {"present": True, "public_only": True, "key_type": kind, "addresses": addresses, "error": None}
    except Exception:
        try:
            from bitcoinlib.keys import HDKey
            root = HDKey.from_wif(value)
            addresses = []
            for branch in list(branches)[:2]:
                for index in range(index_start, index_start + min(index_count, 100)):
                    child = root.key_for_path(f"m/{int(branch)}/{index}")
                    addresses.append({"path": f"m/{int(branch)}/{index}", "address": child.address()})
            return {"present": True, "public_only": True, "key_type": kind, "addresses": addresses, "error": None}
        except Exception:
            return {"present": True, "public_only": True, "key_type": kind, "addresses": [], "error": "Extended key could not be validated locally"}


def analyze_extended_key(value: str | None):
    kind = classify_extended_key(value)
    if not kind:
        return ExtendedKeyAnalysisResult(present=False, public_verification_only=True)
    network = "testnet" if kind in ("tpub", "upub", "vpub", "tprv") else "bitcoin"
    address_type = {"xpub": "legacy-or-profile-dependent", "ypub": "wrapped-segwit", "zpub": "segwit", "xprv": "legacy-or-profile-dependent", "yprv": "wrapped-segwit", "zprv": "segwit"}.get(kind)
    try:
        from embit import bip32
        fingerprint = bip32.HDKey.from_base58(value).my_fingerprint.hex()
    except Exception:
        try:
            from bitcoinlib.keys import HDKey
            fingerprint = HDKey.from_wif(value).fingerprint.hex()
        except Exception:
            fingerprint = None
    return ExtendedKeyAnalysisResult(present=True, key_type=kind, network=network, address_type=address_type, checksum_valid=None, public_verification_only=True, fingerprint=fingerprint)
