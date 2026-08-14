"""Feasibility-first classification; no candidate generation occurs here."""

from math import ceil, log2

from .models import FeasibilityResult, RecoveryClassification, WalletEvidence


def checksum_bits_for_words(word_count: int) -> int:
    return word_count // 3 if word_count in (12, 15, 18, 21, 24) else 0


def partial_mnemonic_feasibility(*, mnemonic_length: int, unknown_word_count: int, address_available: bool = False):
    raw = 2048 ** unknown_word_count
    checksum_bits = checksum_bits_for_words(mnemonic_length)
    reduced = max(1, raw // (1 << checksum_bits))
    bits = log2(reduced) if reduced else 0
    if unknown_word_count == 0:
        classification = RecoveryClassification.RECOVERABLE_CONFIGURATION
        explanation = "No mnemonic words are missing; investigate derivation and passphrase configuration."
        action = "Verify the supplied mnemonic locally across known wallet paths."
        allowed = True
    elif reduced <= (1 << 20) and address_available:
        classification = RecoveryClassification.RECOVERABLE_PARTIAL_MNEMONIC
        explanation = "The checksum-reduced candidate population is small enough for a bounded owner-controlled exercise."
        action = "Generate only checksum-valid candidates inside the active owner session and verify public identifiers."
        allowed = True
    elif reduced <= (1 << 32) and address_available:
        classification = RecoveryClassification.CONDITIONALLY_FEASIBLE
        explanation = "The candidate population is bounded but requires measured local throughput and explicit owner confirmation."
        action = "Obtain stronger constraints before any bounded work; do not start unrestricted generation."
        allowed = False
    else:
        classification = RecoveryClassification.COMPUTATIONALLY_INFEASIBLE
        explanation = "The remaining candidate population is too large for a justified local recovery operation."
        action = "Gather more mnemonic positions, passphrase evidence, derivation details, or generator provenance."
        allowed = False
    return FeasibilityResult(classification=classification, candidate_count=reduced, effective_bits=bits, explanation=explanation, recommended_action=action, expensive_work_allowed=allowed), raw, checksum_bits, reduced


def classify_evidence(evidence: WalletEvidence, *, partial_unknown_count: int | None = None):
    if evidence.known_addresses and (evidence.extended_public_key or evidence.output_descriptor or evidence.watch_only_export):
        return FeasibilityResult(classification=RecoveryClassification.WALLET_ARTIFACT_RECOVERY, effective_bits=256, explanation="Public extended-key, descriptor, or watch-only evidence can constrain verification without exposing private material.", recommended_action="Parse public metadata and compare derived public identifiers locally.", expensive_work_allowed=True)
    if evidence.complete_mnemonic and evidence.known_addresses:
        if evidence.known_derivation_path:
            classification = RecoveryClassification.RECOVERABLE_DERIVATION_PATH
        else:
            classification = RecoveryClassification.RECOVERABLE_CONFIGURATION
        return FeasibilityResult(classification=classification, effective_bits=256, explanation="Secret entropy recovery is unnecessary; derive owner-supplied public identifiers across bounded wallet configurations.", recommended_action="Investigate BIP39 passphrase and standard wallet derivation paths locally.", expensive_work_allowed=True)
    if evidence.partial_mnemonic:
        unknown = partial_unknown_count if partial_unknown_count is not None else 0
        return partial_mnemonic_feasibility(mnemonic_length=len(evidence.partial_mnemonic.split()), unknown_word_count=unknown, address_available=bool(evidence.known_addresses))[0]
    report = evidence.entropy_assurance_report or {}
    effective = report.get("maximum_effective_bits") or report.get("preserved_entropy_bits")
    if evidence.known_addresses and effective is not None and effective <= 48 and (evidence.generator_source or report):
        return FeasibilityResult(classification=RecoveryClassification.RECOVERABLE_KNOWN_WEAK_GENERATOR, effective_bits=float(effective), candidate_count=1 << int(effective), explanation="Generator provenance supplies a justified reduced search domain.", recommended_action="Use only a Chain-Trace-owned, bounded generator-specific verifier after explicit owner confirmation.", expensive_work_allowed=True)
    if evidence.known_derivation_path and evidence.complete_mnemonic:
        return FeasibilityResult(classification=RecoveryClassification.RECOVERABLE_DERIVATION_PATH, effective_bits=256, explanation="A known secret with a constrained path is a configuration recovery problem.", recommended_action="Verify the known path and adjacent bounded indices.", expensive_work_allowed=True)
    if evidence.known_addresses:
        return FeasibilityResult(classification=RecoveryClassification.COMPUTATIONALLY_INFEASIBLE, explanation="A public address alone does not justify reducing the normal private-key search space.", recommended_action="Do not search keys; obtain mnemonic, private key, derivation, passphrase, or generator evidence.", expensive_work_allowed=False)
    return FeasibilityResult(classification=RecoveryClassification.INSUFFICIENT_EVIDENCE, explanation="No owner-controlled recovery evidence is sufficient to choose a bounded path.", recommended_action="Supply an owner-held address or secret/configuration evidence.", expensive_work_allowed=False)
