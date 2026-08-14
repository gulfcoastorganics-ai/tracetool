"""Build a wallet fingerprint from public owner evidence."""

from .models import WalletEvidence, WalletFingerprint
from .wallet_profiles import profile_matches


def classify_extended_key(value: str | None):
    if not value:
        return None
    prefix = value[:4]
    return {"xpub": "xpub", "ypub": "ypub", "zpub": "zpub", "tpub": "tpub", "upub": "upub", "vpub": "vpub", "xprv": "xprv", "yprv": "yprv", "zprv": "zprv", "tprv": "tprv"}.get(prefix)


def build_fingerprint(evidence: WalletEvidence):
    networks = [evidence.network] if evidence.network else []
    addresses = evidence.known_addresses
    if any(address.lower().startswith("0x") for address in addresses) and "ethereum" not in networks:
        networks.append("ethereum")
    if any(address.lower().startswith("bc1") or address.startswith(("1", "3")) for address in addresses) and "bitcoin" not in networks:
        networks.append("bitcoin")
    if evidence.wallet_application and "solana" in evidence.wallet_application.lower() and "solana" not in networks:
        networks.append("solana")
    key_type = classify_extended_key(evidence.extended_public_key or evidence.extended_private_key)
    address_type = []
    if key_type in ("zpub", "zprv") or any(address.lower().startswith("bc1q") for address in addresses):
        address_type.append("segwit")
    if key_type in ("ypub", "yprv"):
        address_type.append("wrapped-segwit")
    if any(address.lower().startswith("0x") for address in addresses):
        address_type.append("evm")
    likely = profile_matches(application=evidence.wallet_application, network=evidence.network)
    year = evidence.approximate_creation_date.year if evidence.approximate_creation_date else None
    confidence = min(0.98, 0.2 + (0.2 if addresses else 0) + (0.2 if evidence.network else 0) + (0.2 if evidence.wallet_application else 0) + (0.2 if key_type or evidence.output_descriptor else 0))
    return WalletFingerprint(networks=networks, address_types=address_type, wallet_applications=[evidence.wallet_application] if evidence.wallet_application else [], likely_profiles=[profile.id for profile in likely], known_address_count=len(addresses), extended_key_type=key_type, master_fingerprint=evidence.master_fingerprint, descriptor_present=bool(evidence.output_descriptor), transaction_evidence_count=len(evidence.transaction_ids), creation_year=year, account_hint=None, branch_hint=None, evidence_strength=confidence)
