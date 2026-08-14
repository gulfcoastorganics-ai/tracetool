"""Connect entropy-assurance evidence to recovery feasibility."""

from .models import GeneratorAnalysisResult, GeneratorAnalysisRequest, RecoveryClassification


def analyze_generator(request: GeneratorAnalysisRequest):
    report = request.entropy_assurance_report or {}
    effective = report.get("maximum_effective_bits") or report.get("preserved_entropy_bits")
    evidence = []
    if request.generator_source:
        evidence.append("authorized generator source supplied")
    if effective is not None:
        evidence.append(f"entropy assurance bounds effective entropy at {effective} bits")
    if request.known_wallet_application:
        evidence.append(f"wallet application identified: {request.known_wallet_application}")
    if effective is not None and effective <= 48 and request.known_address_available and (request.generator_source or report):
        classification = RecoveryClassification.RECOVERABLE_KNOWN_WEAK_GENERATOR
        display = f"2^{int(effective)} candidates"
        recommendation = "Build a bounded generator-specific plan only after owner confirmation and keep candidate secrets internal."
    elif effective is not None and effective >= 128:
        classification = RecoveryClassification.COMPUTATIONALLY_INFEASIBLE
        display = f"2^{int(effective)} candidates"
        recommendation = "Do not search; focus on owner-held configuration, mnemonic, passphrase, or backup evidence."
    else:
        classification = RecoveryClassification.INSUFFICIENT_EVIDENCE
        display = "unknown candidate space"
        recommendation = "Obtain stronger provenance and entropy evidence before choosing a recovery operation."
    return GeneratorAnalysisResult(classification=classification, effective_bits=float(effective) if effective is not None else None, candidate_space_display=display, provenance_evidence=evidence, recommendation=recommendation)
