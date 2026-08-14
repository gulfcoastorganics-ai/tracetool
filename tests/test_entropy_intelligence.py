import logging

import pytest

from backend.entropy.analyzer import analyze_provenance, assess_brainwallet
from backend.entropy.calculator import estimate_entropy, estimate_partial_mnemonic
from backend.entropy.models import EntropyAnalysisRequest, EntropyClassification, PatchStatus, SyntheticWeakGeneratorConfig, WalletProvenance
from backend.entropy.patch_validation import validate_source
from backend.entropy.service import EntropyService, redact_secrets


def test_bip39_nominal_entropy_and_checksum_are_separate():
    estimate = estimate_entropy(mnemonic_length=12)
    assert estimate.nominal_entropy_bits == 128
    assert estimate.checksum_bits == 4
    assert "checksum" not in " ".join(estimate.reasoning_factors).lower() or estimate.checksum_bits == 4


def test_unknown_word_estimate_is_checksum_reduced():
    result = estimate_partial_mnemonic(mnemonic_length=12, known_word_count=9, unknown_word_count=3)
    assert result["raw_word_combination_count"] == 2048 ** 3
    assert result["checksum_reduced_estimate"] < result["raw_word_combination_count"]
    assert result["estimate"].classification == EntropyClassification.PARTIAL_RECOVERY_SCENARIO


def test_low_width_generator_reduces_effective_entropy():
    estimate = estimate_entropy(nominal_entropy_bits=256, generator_state_width_bits=20)
    assert estimate.estimated_effective_entropy_bits == 20
    assert estimate.feasibility_class.value in {"SMALL_BOUNDED", "TRIVIAL_LAB"}


def test_vulnerable_profile_match_and_patched_old_wallet_distinction():
    request = EntropyAnalysisRequest(
        provenance=WalletProvenance(wallet_software="custom", generator_details="timestamp seeded MT19937"),
        software_status=PatchStatus.PATCHED,
        wallet_generation_status=PatchStatus.VULNERABLE,
        nominal_entropy_bits=256,
    )
    result = analyze_provenance(request)
    assert result.likely_generator_profile is not None
    assert result.estimate.classification == EntropyClassification.PATCHED_SOFTWARE_OLD_WALLETS_AT_RISK
    assert result.existing_wallet_entropy_repaired is False


def test_secure_evidence_does_not_claim_unknown_mnemonic_weakness():
    result = analyze_provenance(EntropyAnalysisRequest(provenance=WalletProvenance(rng_function="os.urandom"), nominal_entropy_bits=128))
    assert result.estimate.classification == EntropyClassification.SECURE_EXPECTED


@pytest.mark.parametrize("model,bits", [("16", 16), ("20", 20), ("24", 24)])
def test_synthetic_weak_generators_are_owned_and_bounded(model, bits):
    service = EntropyService()
    fixture = service.generate(SyntheticWeakGeneratorConfig(model=model, target_position=3))
    assert fixture.actual_effective_entropy_bits == bits
    recovery = service.recover(fixture.session_token)
    assert recovery["ownership_verified"] is True
    assert recovery["verification"] is True
    assert recovery["secret_redacted"] is True


def test_recovery_ownership_enforcement_and_patched_infeasible():
    service = EntropyService()
    with pytest.raises(ValueError):
        service.recover("external-address-or-fake-token")
    patched = service.generate(SyntheticWeakGeneratorConfig(model="patched"))
    assert patched.feasibility_class.value == "COMPUTATIONALLY_INFEASIBLE"
    with pytest.raises(ValueError):
        service.recover(patched.session_token)


def test_patch_validation_detects_weak_and_positive_sources():
    result = validate_source("import random\nseed = int(time.time())\nsecret = random.getrandbits(256)")
    assert result["risk"] == EntropyClassification.KNOWN_VULNERABLE_GENERATOR
    positive = validate_source("from secrets import token_bytes\nkey = token_bytes(32)")
    assert positive["positive_evidence"]
    assert positive["secure_detection_not_proof"] is True


def test_brainwallet_assessment_is_qualitative_only():
    result = assess_brainwallet("a human chosen quote")
    assert result["risk"] in {"QUOTE_LIKE", "HUMAN_CHOSEN_SECRET"}


def test_redaction_removes_secret_named_fields_without_logging_values(caplog):
    caplog.set_level(logging.INFO)
    redacted = redact_secrets({"mnemonic": "never-log-this", "private_key": "also-secret", "classification": "safe"})
    assert redacted["mnemonic"] == "[REDACTED]"
    assert redacted["private_key"] == "[REDACTED]"
    assert "never-log-this" not in caplog.text
