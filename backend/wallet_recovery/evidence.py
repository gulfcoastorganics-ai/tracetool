"""Evidence normalization and owner-control checks."""

from .models import EvidenceItem, WalletEvidence


def summarize_evidence(evidence: WalletEvidence):
    items = []
    if evidence.known_addresses:
        items.append(EvidenceItem(kind="known_public_address", description=f"{len(evidence.known_addresses)} owner-supplied public address(es)", confidence=0.9))
    if evidence.network:
        items.append(EvidenceItem(kind="network", description=evidence.network, confidence=0.8))
    if evidence.wallet_application:
        items.append(EvidenceItem(kind="wallet_application", description=evidence.wallet_application, confidence=0.7))
    if evidence.approximate_creation_date:
        items.append(EvidenceItem(kind="creation_date", description="approximate creation date supplied", confidence=0.5))
    if evidence.known_derivation_path or evidence.wallet_type:
        items.append(EvidenceItem(kind="derivation_configuration", description="known derivation path or wallet type", confidence=0.85))
    if evidence.complete_mnemonic:
        items.append(EvidenceItem(kind="complete_mnemonic", description="complete mnemonic supplied in active session", confidence=1.0))
    elif evidence.partial_mnemonic:
        items.append(EvidenceItem(kind="partial_mnemonic", description="partial mnemonic supplied in active session", confidence=0.9))
    if evidence.passphrase_known or evidence.passphrase_hints:
        items.append(EvidenceItem(kind="passphrase", description="passphrase state or owner hints supplied", confidence=0.6))
    if evidence.generator_source:
        items.append(EvidenceItem(kind="generator_source", description="authorized generator/source supplied", confidence=0.9))
    if evidence.entropy_assurance_report:
        items.append(EvidenceItem(kind="entropy_assurance", description="entropy assurance report supplied", confidence=0.9))
    if evidence.private_key_available:
        items.append(EvidenceItem(kind="private_key", description="private key available in active owner session", confidence=1.0))
    return items


def owner_control_is_sufficient(evidence: WalletEvidence) -> bool:
    return bool(evidence.known_addresses or evidence.complete_mnemonic or evidence.partial_mnemonic or evidence.private_key_available)
