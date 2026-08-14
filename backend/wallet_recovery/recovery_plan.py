"""Ordered, bounded recovery plans."""

from .models import RecoveryClassification, RecoveryPlanResult, WalletEvidence


def build_plan(evidence: WalletEvidence, classification: RecoveryClassification):
    steps = []
    blocked = ["arbitrary private-key search", "blockchain balance lookup", "external mnemonic dataset search"]
    if evidence.complete_mnemonic:
        steps.extend(["Validate the complete mnemonic locally", "Explore standard wallet derivation paths within configured limits", "Compare derived public identifiers to owner-supplied addresses", "Test the empty passphrase and only owner-supplied passphrase candidates"])
    elif evidence.partial_mnemonic:
        steps.extend(["Calculate checksum-reduced candidate population", "Require owner confirmation before any bounded completion", "Verify each candidate only against owner-supplied public identifiers"])
    elif evidence.generator_source or evidence.entropy_assurance_report:
        steps.extend(["Review generator provenance and entropy assurance", "Confirm the effective search domain is independently justified", "Build a bounded verifier only if the domain is below policy limits"])
    else:
        steps.append("Gather owner-held mnemonic, backup, derivation, passphrase, or generator evidence")
    return RecoveryPlanResult(classification=classification, ordered_steps=steps, blocked_operations=blocked)
