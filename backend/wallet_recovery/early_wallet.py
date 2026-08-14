"""Historical wallet identification from owner-supplied public evidence.

This module ranks recovery *hypotheses*. It does not derive private keys and
does not treat a wallet's age as a cryptographic shortcut.
"""

from dataclasses import dataclass
from datetime import date
from typing import Any

from .artifact_detector import detect_artifact


@dataclass(frozen=True)
class HistoricalWalletProfile:
    id: str
    name: str
    applications: tuple[str, ...]
    networks: tuple[str, ...]
    first_year: int
    last_year: int
    artifact_hints: tuple[str, ...]
    address_types: tuple[str, ...]
    seed_formats: tuple[str, ...]
    recovery_families: tuple[str, ...]
    notes: str


# Dates are deliberately broad compatibility windows, not claims that every
# release in a window had identical behavior.
HISTORICAL_PROFILES = (
    HistoricalWalletProfile("bitcoin-core-legacy", "Bitcoin Core legacy wallet", ("bitcoin core", "bitcoin-qt", "core"), ("bitcoin",), 2009, 2013, ("bitcoin-core-or-binary-wallet", "bitcoin-core-wallet", "wallet.dat"), ("legacy",), ("LEGACY_KEYPOOL",), ("legacy keypool / wallet.dat migration",), "Legacy keypool wallets require Core-native interpretation."),
    HistoricalWalletProfile("bitcoin-core-hd-legacy", "Bitcoin Core HD legacy wallet", ("bitcoin core", "bitcoin-qt", "core"), ("bitcoin",), 2013, 2022, ("bitcoin-core-or-binary-wallet", "wallet.dat"), ("legacy", "segwit"), ("BIP32",), ("BIP32 / Core migration",), "Distinguish legacy BDB handling from descriptor-wallet handling."),
    HistoricalWalletProfile("bitcoin-core-descriptor", "Bitcoin Core descriptor wallet", ("bitcoin core", "bitcoin-qt", "core"), ("bitcoin",), 2020, 2026, ("bitcoin-core-descriptor", "descriptor-sqlite"), ("legacy", "segwit", "taproot"), ("DESCRIPTOR",), ("descriptor / policy",), "Descriptor metadata is public evidence; private recovery remains Core-native."),
    HistoricalWalletProfile("electrum-legacy", "Electrum historical wallet", ("electrum",), ("bitcoin",), 2011, 2016, ("electrum-or-wallet-file", ".wallet"), ("legacy", "segwit"), ("ELECTRUM_SEED_VERSION",), ("Electrum seed-version / wallet file",), "Electrum phrases are not malformed BIP39 phrases."),
    HistoricalWalletProfile("electrum-modern", "Electrum wallet", ("electrum",), ("bitcoin",), 2014, 2026, ("electrum-or-wallet-file", ".wallet"), ("legacy", "segwit", "multisig"), ("ELECTRUM_SEED_VERSION",), ("Electrum keystore / watch-only",), "Wallet-file metadata can constrain keystore and derivation behavior."),
    HistoricalWalletProfile("armory", "Armory wallet", ("armory",), ("bitcoin",), 2012, 2018, ("armory", ".wallet"), ("legacy",), ("ARMORY_WALLET",), ("Armory wallet database / paper backup",), "Armory recovery requires Armory-compatible artifact semantics."),
    HistoricalWalletProfile("multibit", "MultiBit historical wallet", ("multibit", "multibit hd"), ("bitcoin",), 2011, 2017, ("multibit", ".wallet", ".key"), ("legacy",), ("MULTIBIT",), ("legacy key / MultiBit backup",), "Historical MultiBit formats must not be interpreted as modern BIP39 by default."),
    HistoricalWalletProfile("paper-wallet", "Paper wallet", ("paper wallet", "paper"), ("bitcoin",), 2011, 2026, ("paper",), ("legacy",), ("RAW_PRIVATE_KEY_OR_ENTROPY",), ("single printed key/address",), "A paper-wallet hypothesis is based on owner evidence, not address appearance alone."),
    HistoricalWalletProfile("bip39-hardware", "BIP39 hardware wallet", ("ledger", "ledger live", "trezor", "trezor suite", "coldcard", "jade", "keepkey"), ("bitcoin", "ethereum", "solana"), 2014, 2026, ("watch-only-or-account-export", "hardware-export"), ("segwit", "taproot", "evm"), ("BIP39",), ("BIP39 / account discovery / xpub",), "BIP39 validity still does not prove source entropy or the passphrase."),
)


def _year(value: date | int | None) -> int | None:
    if isinstance(value, int):
        return value
    return value.year if value else None


def _artifact_signals(evidence) -> tuple[set[str], dict[str, Any]]:
    signals: set[str] = set()
    metadata: dict[str, Any] = {}
    supplied = (evidence.wallet_artifact_type or "").lower()
    if supplied:
        signals.add(supplied)
    path = evidence.wallet_artifact_path
    if path:
        detected = detect_artifact(path)
        if detected.get("artifact_type"):
            signals.add(str(detected["artifact_type"]).lower())
        metadata = {"artifact_type": detected.get("artifact_type"), "exists": detected.get("detected"), "metadata_only": True}
    return signals, metadata


def identify_early_wallet(evidence) -> dict[str, Any]:
    """Rank historical wallet implementations using non-secret evidence."""
    app = (evidence.wallet_application or "").lower()
    network = (evidence.network or "").lower()
    year = _year(evidence.approximate_creation_date)
    tx_years = [_year(item) for item in evidence.transaction_dates]
    tx_years = [item for item in tx_years if item is not None]
    artifact_signals, artifact_metadata = _artifact_signals(evidence)
    address_types = set()
    for address in evidence.known_addresses:
        lower = address.lower()
        if lower.startswith("bc1q"): address_types.add("segwit")
        elif lower.startswith("bc1p"): address_types.add("taproot")
        elif lower.startswith("0x"): address_types.add("evm")
        elif lower.startswith(("1", "3")): address_types.add("legacy")
    if evidence.extended_public_key:
        key = evidence.extended_public_key[:4].lower()
        address_types.update({"segwit"} if key in {"zpub", "vpub"} else {"legacy"} if key in {"xpub", "tpub"} else {"wrapped-segwit"} if key in {"ypub", "upub"} else set())
    if evidence.output_descriptor:
        text = evidence.output_descriptor.lower()
        if "tr(" in text: address_types.add("taproot")
        if "wpkh(" in text: address_types.add("segwit")
        if "pkh(" in text: address_types.add("legacy")

    rows = []
    for profile in HISTORICAL_PROFILES:
        score = 0
        reasons: list[str] = []
        contradictions: list[str] = []
        if app and any(alias in app for alias in profile.applications):
            score += 50; reasons.append("wallet software matches profile")
        elif app and profile.name.lower() not in app:
            score -= 5
        if network and network in profile.networks:
            score += 12; reasons.append("network is supported by profile")
        elif network:
            score -= 25; contradictions.append("network conflicts with profile")
        if year is not None:
            if profile.first_year <= year <= profile.last_year:
                score += 22; reasons.append("creation year falls in compatibility window")
            else:
                score -= 12; contradictions.append("creation year is outside compatibility window")
        if tx_years:
            if any(profile.first_year <= tx_year <= profile.last_year for tx_year in tx_years):
                score += 8; reasons.append("transaction era is compatible")
            else:
                score -= 5; contradictions.append("transaction era is not compatible")
        matched_artifacts = [hint for hint in profile.artifact_hints if any(hint in signal or signal in hint for signal in artifact_signals)]
        if matched_artifacts:
            score += 30; reasons.append("surviving artifact type matches")
        if address_types & set(profile.address_types):
            score += 10; reasons.append("public address/script family is compatible")
        if evidence.output_descriptor and "descriptor" in profile.recovery_families:
            score += 18; reasons.append("descriptor evidence matches")
        if evidence.master_fingerprint or evidence.extended_public_key:
            if "xpub" in " ".join(profile.recovery_families) or "descriptor" in " ".join(profile.recovery_families):
                score += 6; reasons.append("public key evidence can constrain this profile")
        if evidence.wallet_era and evidence.wallet_era.lower() in profile.id:
            score += 12; reasons.append("owner-supplied era label matches")
        if not reasons:
            continue
        confidence = max(0.0, min(0.99, 0.25 + max(score, 0) / 130))
        rows.append({"profile_id": profile.id, "name": profile.name, "score": score, "confidence": round(confidence, 3), "reasons": reasons, "contradictions": contradictions, "recovery_families": list(profile.recovery_families), "seed_formats": list(profile.seed_formats), "compatibility_window": [profile.first_year, profile.last_year], "notes": profile.notes})
    rows.sort(key=lambda item: (-item["score"], item["profile_id"]))
    if not rows:
        status = "INSUFFICIENT_EVIDENCE"
    elif rows[0]["score"] >= 70 and (len(rows) == 1 or rows[0]["score"] - rows[1]["score"] >= 15):
        status = "IDENTIFIED"
    elif rows[0]["score"] >= 35:
        status = "LIKELY"
    else:
        status = "AMBIGUOUS"
    recommended = []
    for row in rows[:3]:
        recommended.extend(row["recovery_families"])
    return {"status": status, "age_is_evidence_only": True, "hypotheses": rows[:8], "recommended_recovery_families": list(dict.fromkeys(recommended)), "evidence_used": {"network": evidence.network, "wallet_application": evidence.wallet_application, "creation_year": year, "transaction_years": tx_years, "address_types": sorted(address_types), "artifact": artifact_metadata, "public_address_count": len(evidence.known_addresses), "has_xpub": bool(evidence.extended_public_key), "has_descriptor": bool(evidence.output_descriptor), "master_fingerprint_present": bool(evidence.master_fingerprint)}, "next_evidence": ["wallet file or watch-only export", "first known receiving address and transaction date", "xpub/origin or descriptor", "exact wallet application/version"], "secrets_persisted": False}
