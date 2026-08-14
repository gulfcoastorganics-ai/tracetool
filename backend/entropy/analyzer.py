"""Conservative provenance analyzer."""

from .calculator import estimate_entropy
from .models import EntropyAnalysisRequest, EntropyAnalysisResult, EntropyClassification, FeasibilityAssessment, PatchStatus
from .provenance import match_profiles


def assess_brainwallet(phrase_method: str):
    """Qualitative assessment only; never expands a phrase into an attack list."""
    import re
    text = phrase_method.strip()
    lower = text.lower()
    if not text:
        return {"risk": "UNKNOWN", "confidence": 0.1, "reasoning": ["No phrase-generation method supplied."]}
    if any(token in lower for token in ("quote", "song", "poem", "birthday", "password", "family", "human")):
        return {"risk": "QUOTE_LIKE", "confidence": 0.85, "reasoning": ["The method describes human-selected or culturally memorable text."]}
    if re.fullmatch(r"[a-zA-Z ]+", text) and len(text.split()) >= 2:
        return {"risk": "DICTIONARY_LIKE", "confidence": 0.7, "reasoning": ["The method is composed of ordinary language words.", "Human choice is not equivalent to CSPRNG entropy."]}
    return {"risk": "UNKNOWN", "confidence": 0.25, "reasoning": ["The supplied method is insufficient to establish provenance."]}


def analyze_provenance(request: EntropyAnalysisRequest) -> EntropyAnalysisResult:
    matches = match_profiles(request.provenance, request.evidence)
    supporting = [reason for _, _, reasons in matches for reason in reasons]
    contradicting = [item.statement for item in request.evidence if not item.supports]
    confidence = min(0.98, (matches[0][0] / 10) if matches else 0.2)
    profile = matches[0][1] if matches else None
    classification = EntropyClassification.INSUFFICIENT_EVIDENCE
    if profile:
        classification = EntropyClassification.KNOWN_VULNERABLE_GENERATOR
    elif request.generator_state_width_bits and request.generator_state_width_bits < 128:
        classification = EntropyClassification.REDUCED_ENTROPY
    elif request.provenance.rng_function and any(term in request.provenance.rng_function.lower() for term in ("os.urandom", "secrets", "getrandom", "getrandomvalues")):
        classification = EntropyClassification.SECURE_EXPECTED
        confidence = max(confidence, 0.8)
    elif request.nominal_entropy_bits and request.nominal_entropy_bits >= 128:
        classification = EntropyClassification.INSUFFICIENT_EVIDENCE
    if request.software_status == PatchStatus.PATCHED and request.wallet_generation_status == PatchStatus.VULNERABLE:
        classification = EntropyClassification.PATCHED_SOFTWARE_OLD_WALLETS_AT_RISK
    estimate = estimate_entropy(
        mnemonic_length=request.mnemonic_length, nominal_entropy_bits=request.nominal_entropy_bits,
        unknown_mnemonic_words=request.unknown_mnemonic_words,
        generator_state_width_bits=request.generator_state_width_bits,
        documented_generator_state_reduction=request.documented_generator_state_reduction,
        constraints=request.constraints, confidence=confidence, classification=classification,
        extra_factors=["mnemonic validity and entropy provenance are separate claims"],
    )
    if profile and profile.known_state_width_bits and request.generator_state_width_bits is None:
        estimate = estimate_entropy(mnemonic_length=request.mnemonic_length, nominal_entropy_bits=request.nominal_entropy_bits, generator_state_width_bits=profile.known_state_width_bits, constraints=request.constraints, confidence=confidence, classification=classification, extra_factors=estimate.reasoning_factors + ["matched profile supplies a state-width bound"])
    if classification == EntropyClassification.SECURE_EXPECTED:
        recommendation = "No weakness is established. Preserve provenance evidence and use a newly generated wallet if provenance remains uncertain."
    elif classification in (EntropyClassification.KNOWN_VULNERABLE_GENERATOR, EntropyClassification.PATCHED_SOFTWARE_OLD_WALLETS_AT_RISK):
        recommendation = "Do not treat a software patch as repairing old wallet material; migrate funds to a newly generated wallet after independently verifying ownership."
    else:
        recommendation = "Do not launch an expensive search. Gather generator/source evidence and treat the mnemonic as sensitive."
    repaired = False
    return EntropyAnalysisResult(provenance=request.provenance, likely_generator_profile=profile, possible_generator_profiles=[item[1] for item in matches], supporting_evidence=supporting, contradicting_evidence=contradicting, generator_confidence=confidence, effective_entropy_impact="Estimated from disclosed constraints only; mnemonic text alone does not prove weak provenance.", estimate=estimate, feasibility=FeasibilityAssessment(feasibility_class=estimate.feasibility_class, explanation="Feasibility is a policy classification, not a runtime prediction.", warnings=["Measured throughput and derivation path can materially change elapsed time."]), software_status=request.software_status, wallet_generation_status=request.wallet_generation_status, existing_wallet_entropy_repaired=repaired, recommended_response=recommendation)
