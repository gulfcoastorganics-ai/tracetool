from pathlib import Path

import pytest

from backend.wallet_recovery.derivation import explore_derivations
from backend.wallet_recovery.candidate_space import estimate_candidate_space
from backend.wallet_recovery.constraints import passphrase_variants, structured_passphrase_hypotheses
from backend.wallet_recovery.mnemonic_candidates import candidate_word_sets, estimate_raw_combinations, count_valid_mnemonics
from backend.wallet_recovery.descriptors import analyze_descriptor, derive_descriptor_addresses
from backend.wallet_recovery.extended_keys import analyze_extended_key, derive_extended_key_addresses
from backend.wallet_recovery.feasibility import partial_mnemonic_feasibility
from backend.wallet_recovery.fingerprint import build_fingerprint
from backend.wallet_recovery.artifact_detector import detect_artifact
from backend.wallet_recovery.candidate_ranker import rank_candidates
from backend.wallet_recovery.models import (
    AddressVerificationRequest, DerivationExploreRequest, GeneratorAnalysisRequest,
    MnemonicAnalysisRequest, RecoveryAnalysisRequest, RecoveryClassification,
    RecoveryPlanRequest, RecoverySessionRequest, WalletEvidence, RecoveryBudget, RecoveryServiceResult,
)
from backend.wallet_recovery.redaction import redact
from backend.wallet_recovery.report import persist_report
from backend.wallet_recovery.service import wallet_recovery_service
from backend.wallet_recovery.chain_verifier import InMemoryPublicHistoryProvider, verify_public_history
from backend.wallet_recovery.artifact_adapters.ethereum_keystore import EthereumV3KeystoreAdapter
from backend.wallet_recovery.path_hypotheses import rank_path_hypotheses
from backend.wallet_recovery.formats import classify_backup, BackupFormat
from backend.wallet_recovery.electrum import detect_electrum_seed
from backend.wallet_recovery.slip39 import inspect_slip39_shares, reconstruct_slip39
from backend.wallet_recovery.descriptors import derive_descriptor_addresses
from backend.wallet_recovery.policy_artifacts import inspect_bip388, inspect_bsms
from backend.wallet_recovery.artifact_adapters.electrum import ElectrumArtifactAdapter
from backend.wallet_recovery.artifact_adapters.bitcoin_core import BitcoinCoreArtifactAdapter
from backend.wallet_recovery.wallet_behavior import build_behavior_fingerprint
from backend.wallet_recovery.hypothesis_graph import HypothesisNode, RecoveryHypothesisGraph
from backend.wallet_recovery.proof import RecoveryProofBundle
from backend.wallet_recovery.early_wallet import identify_early_wallet


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_public_address_only_is_not_a_search_authorization():
    result = wallet_recovery_service.analyze(RecoveryAnalysisRequest(evidence=WalletEvidence(known_addresses=["0x1234567890123456789012345678901234567890"], network="ethereum")))
    assert result.classification == RecoveryClassification.COMPUTATIONALLY_INFEASIBLE
    assert result.feasibility.expensive_work_allowed is False
    assert result.service_result == RecoveryServiceResult.CRYPTOGRAPHICALLY_INFEASIBLE


def test_complete_mnemonic_address_mismatch_is_configuration_recovery():
    address = explore_derivations(MNEMONIC, networks=["ethereum"], index_count=1)[0].address
    result = wallet_recovery_service.analyze(RecoveryAnalysisRequest(evidence=WalletEvidence(known_addresses=[address], network="ethereum", complete_mnemonic=MNEMONIC)))
    assert result.classification == RecoveryClassification.RECOVERABLE_CONFIGURATION
    assert "configuration" in result.diagnosis.lower()
    assert result.service_result == RecoveryServiceResult.RECOVERY_FEASIBLE
    assert result.private_evidence == "SUFFICIENT"
    assert result.public_match_status == "PENDING"


def test_partial_mnemonic_checksum_reduces_candidate_population():
    result, raw, checksum, reduced = partial_mnemonic_feasibility(mnemonic_length=24, unknown_word_count=1, address_available=True)
    assert raw == 2048
    assert checksum == 8
    assert reduced == 8
    assert result.classification == RecoveryClassification.RECOVERABLE_PARTIAL_MNEMONIC


def test_large_partial_mnemonic_is_rejected_before_generation():
    result, _, _, _ = partial_mnemonic_feasibility(mnemonic_length=24, unknown_word_count=12, address_available=False)
    assert result.classification == RecoveryClassification.COMPUTATIONALLY_INFEASIBLE
    assert result.expensive_work_allowed is False


def test_known_weak_generator_uses_entropy_assurance_bound():
    result = wallet_recovery_service.analyze(RecoveryAnalysisRequest(evidence=WalletEvidence(known_addresses=["1owneraddress"], network="bitcoin", entropy_assurance_report={"maximum_effective_bits": 32}, generator_source="seed32 -> sha256")))
    assert result.classification == RecoveryClassification.RECOVERABLE_KNOWN_WEAK_GENERATOR
    assert result.feasibility.effective_bits == 32


def test_owner_session_derivation_explorer_matches_public_identifier():
    address = explore_derivations(MNEMONIC, networks=["ethereum"], index_count=1)[0].address
    session = wallet_recovery_service.create_session(RecoverySessionRequest(evidence=WalletEvidence(known_addresses=[address], network="ethereum", complete_mnemonic=MNEMONIC)))
    result = wallet_recovery_service.derive(DerivationExploreRequest(session_token=session.session_token, networks=["ethereum"], index_count=1))
    assert result.status.value == "MATCH"
    assert result.matches[0].address.lower() == address.lower()
    assert result.service_result == RecoveryServiceResult.RECOVERY_CONFIRMED
    assert result.public_match_status == "UNIQUE_PUBLIC_MATCH"


def test_address_verification_returns_redacted_secret():
    address = explore_derivations(MNEMONIC, networks=["ethereum"], index_count=1)[0].address
    session = wallet_recovery_service.create_session(RecoverySessionRequest(evidence=WalletEvidence(known_addresses=[address], network="ethereum", complete_mnemonic=MNEMONIC)))
    result = wallet_recovery_service.verify_address(AddressVerificationRequest(session_token=session.session_token, network="ethereum", address=address, derivation_path="m/44'/60'/0'/0/0"))
    assert result.status.value == "MATCH"
    assert result.secret == "REDACTED"
    assert result.export_requires_explicit_local_reveal is True


def test_session_rejects_without_owner_evidence():
    with pytest.raises(ValueError):
        wallet_recovery_service.create_session(RecoverySessionRequest(evidence=WalletEvidence()))


def test_derivation_limits_are_hard_bounded():
    session = wallet_recovery_service.create_session(RecoverySessionRequest(evidence=WalletEvidence(known_addresses=["0xabc"], complete_mnemonic=MNEMONIC)))
    with pytest.raises(ValueError):
        wallet_recovery_service.derive(DerivationExploreRequest(session_token=session.session_token, networks=["bitcoin", "ethereum", "solana"], account_count=3, index_count=20))


def test_mnemonic_analysis_has_no_candidate_generation_side_effect():
    result = wallet_recovery_service.analyze_mnemonic(MnemonicAnalysisRequest(mnemonic_length=24, known_word_count=23, expected_address_available=True))
    assert result.unknown_word_count == 1
    assert result.checksum_reduced_candidate_count == 8
    assert result.checksum_is_not_entropy is True


def test_plan_blocks_generic_search_and_network_queries():
    result = wallet_recovery_service.build_plan(RecoveryPlanRequest(evidence=WalletEvidence(known_addresses=["0xabc"], network="ethereum")))
    assert "arbitrary private-key search" in result.blocked_operations
    assert result.requires_owner_verification is True


def test_redaction_and_report_do_not_store_sensitive_values(tmp_path: Path):
    cleaned = redact({"mnemonic": MNEMONIC, "private_key": "deadbeef", "address": "0xabc"})
    assert cleaned["mnemonic"] == "REDACTED"
    assert cleaned["private_key"] == "REDACTED"
    report = {"classification": "RECOVERABLE_CONFIGURATION", "mnemonic": MNEMONIC, "secret": "x"}
    path = persist_report(type("Report", (), {"model_dump": lambda self, mode=None: report})(), tmp_path)
    contents = path.read_text()
    assert MNEMONIC not in contents
    assert "deadbeef" not in contents


def test_wallet_fingerprint_and_profile_evidence():
    fingerprint = build_fingerprint(WalletEvidence(known_addresses=["bc1qowner"], network="bitcoin", wallet_application="Ledger Live", extended_public_key="zpub-example"))
    assert "bitcoin" in fingerprint.networks
    assert fingerprint.extended_key_type == "zpub"
    assert "segwit" in fingerprint.address_types
    assert "ledger-btc-segwit" in fingerprint.likely_profiles


def test_extended_key_descriptor_and_artifact_metadata_are_public_only():
    key = analyze_extended_key("xpub-example")
    assert key.present is True
    assert key.public_verification_only is True
    descriptor = analyze_descriptor("wpkh([abcd/84'/0'/0']xpub/0/*)")
    assert descriptor["present"] is True
    assert "wpkh" in descriptor["script_types"]
    artifact = detect_artifact("/does/not/exist/wallet.json")
    assert artifact["secret_decryption_attempted"] is False


def test_candidate_space_reports_rich_constraints():
    result = estimate_candidate_space(mnemonic_length=24, unknown_words=1, profile_count=3, addresses_per_profile=100, address_evidence=True)
    assert result.candidate_space_before_constraints == 2048
    assert result.candidate_space_after_checksum == 8
    assert result.derivation_profiles == 3
    assert result.estimated_derivations == 2400
    assert result.strongest_verification_evidence == "KNOWN_ADDRESS"
    assert result.feasible is True


def test_passphrase_variants_are_owner_supplied_only_and_matches_rank_first():
    variants = passphrase_variants("Wallet", capitalization=True, whitespace=True)
    assert "Wallet" in variants
    assert "wallet" in variants
    ranked = rank_candidates([{"address": "other"}, {"address": "OWNER"}], known_addresses=["owner"])
    assert ranked[0]["candidate"]["address"] == "OWNER"


def test_public_xpub_derivation_produces_only_addresses():
    xpub = "xpub6FrCS2gWHvogbAX8ipHuBmbPvckXLYs5SfEKq1Lp3tneESUXuNNUw67q6Q6r1xHhmoQtByXS7SXes78nuGckLXWEuRPWNfwBo8Cp5QQLPKy"
    result = derive_extended_key_addresses(xpub, index_count=2)
    assert result["public_only"] is True
    assert len(result["addresses"]) == 4
    assert all("private" not in item for item in result["addresses"])


def test_descriptor_expansion_is_bounded_and_public_only():
    xpub = "xpub6FrCS2gWHvogbAX8ipHuBmbPvckXLYs5SfEKq1Lp3tneESUXuNNUw67q6Q6r1xHhmoQtByXS7SXes78nuGckLXWEuRPWNfwBo8Cp5QQLPKy"
    result = derive_descriptor_addresses(f"wpkh({xpub}/0/*)", index_count=2)
    assert result["public_only"] is True
    assert len(result["addresses"]) == 2


def test_structured_passphrase_grammar_is_bounded():
    values = structured_passphrase_hypotheses(components=["oldpassword"], years=[2019], suffixes=["!"], capitalization=True, max_candidates=12)
    assert 0 < len(values) <= 12
    assert all(isinstance(value, str) for value in values)


def test_recovery_budget_separates_seed_and_child_work():
    session = wallet_recovery_service.create_session(RecoverySessionRequest(evidence=WalletEvidence(known_addresses=["0xabc"], complete_mnemonic=MNEMONIC)))
    budget = RecoveryBudget(max_seed_candidates=1, max_pbkdf2_operations=1, max_paths_per_seed=7, max_child_derivations=7)
    result = wallet_recovery_service.derive(DerivationExploreRequest(session_token=session.session_token, networks=["ethereum"], index_count=1, budget=budget))
    assert result.checkpoint["pbkdf2_operations"] == 1
    assert result.checkpoint["budget"]["max_seed_candidates"] == 1


def test_position_aware_checksum_first_generation():
    partial = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?"
    sets = candidate_word_sets(partial)
    assert estimate_raw_combinations(sets) == 2048
    assert count_valid_mnemonics(partial) == 128


def test_partial_executor_finds_owner_match_before_large_search():
    address = explore_derivations(MNEMONIC, networks=["ethereum"], index_count=1)[0].address
    evidence = WalletEvidence(known_addresses=[address], network="ethereum", partial_mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?")
    session = wallet_recovery_service.create_session(RecoverySessionRequest(evidence=evidence))
    result = wallet_recovery_service.derive(DerivationExploreRequest(session_token=session.session_token, networks=["ethereum"], index_count=1, budget=RecoveryBudget(max_seed_candidates=20, max_pbkdf2_operations=20, max_paths_per_seed=7, max_child_derivations=7)))
    assert result.termination.value == "UNIQUE_PUBLIC_MATCH"
    assert result.preflight["raw_combinations"] == 2048
    assert result.preflight["actual_pbkdf2_operations"] == 1
    assert result.candidate_provenance[0]["secret"] == "REDACTED"


def test_partial_executor_requires_public_constraint():
    evidence = WalletEvidence(network="ethereum", partial_mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?")
    session = wallet_recovery_service.create_session(RecoverySessionRequest(evidence=evidence))
    result = wallet_recovery_service.derive(DerivationExploreRequest(session_token=session.session_token, networks=["ethereum"]))
    assert result.termination.value == "COMPUTATIONALLY_INFEASIBLE"


def test_public_history_provider_is_address_only_and_opt_in():
    provider = InMemoryPublicHistoryProvider({("ethereum", "0xabc"): {"used": True, "transactions": [{"txid": "public-only"}], "first_seen": "2021-01-01"}})
    offline = verify_public_history(["0xabc"], network="ethereum", enabled=False, provider=provider)
    assert offline["offline"] is True and offline["checked"] == 0
    online = verify_public_history(["0xabc"], network="ethereum", enabled=True, provider=provider, max_queries=1)
    assert online["history"]["0xabc"]["used"] is True
    assert online["history"]["0xabc"]["transactions"][0]["txid"] == "public-only"


def test_candidate_provenance_separates_confidence_and_match_certainty():
    address = explore_derivations(MNEMONIC, networks=["ethereum"], index_count=1)[0].address
    evidence = WalletEvidence(known_addresses=[address], network="ethereum", partial_mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?")
    session = wallet_recovery_service.create_session(RecoverySessionRequest(evidence=evidence))
    result = wallet_recovery_service.derive(DerivationExploreRequest(session_token=session.session_token, networks=["ethereum"], index_count=1, budget=RecoveryBudget(max_seed_candidates=2, max_pbkdf2_operations=2, max_paths_per_seed=7, max_child_derivations=7)))
    assert result.candidate_provenance[0]["match_certainty"] == "CRYPTOGRAPHIC_PUBLIC_MATCH"


def test_ethereum_v3_keystore_verifies_password_without_returning_private_key():
    from Crypto.Cipher import AES
    from Crypto.Hash import keccak
    from Crypto.Protocol.KDF import scrypt
    password = "fixture-password"
    private = b"\x01" * 32
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    derived = scrypt(password.encode(), salt, 32, N=2**12, r=8, p=1)
    ciphertext = AES.new(derived[:16], AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big")).encrypt(private)
    mac = keccak.new(digest_bits=256, data=derived[16:32] + ciphertext).hexdigest()
    artifact = {"version": 3, "crypto": {"cipher": "aes-128-ctr", "ciphertext": ciphertext.hex(), "cipherparams": {"iv": iv.hex()}, "kdf": "scrypt", "kdfparams": {"dklen": 32, "n": 2**12, "r": 8, "p": 1, "salt": salt.hex()}, "mac": mac}}
    adapter = EthereumV3KeystoreAdapter()
    assert adapter.inspect(artifact).kdf == "scrypt"
    assert adapter.verify_password_candidate(artifact, "wrong").valid is False
    result = adapter.verify_password_candidate(artifact, password)
    assert result.valid is True
    assert "private" not in str(result.public_evidence).lower()
    assert result.secrets_discarded is True


def test_path_hypothesis_engine_prioritizes_zpub_native_segwit():
    paths = rank_path_hypotheses(network="bitcoin", wallet_application="Ledger Live", extended_key_type="zpub", address_types=["segwit"])
    assert paths[0].path_template.startswith("m/84'")
    assert "Ledger profile" in paths[0].reasons


def test_backup_format_classifier_routes_electrum_before_bip39():
    seed = None
    for index in range(10000):
        candidate = f"owner controlled electrum fixture {index}"
        if detect_electrum_seed(candidate)["recognized"]:
            seed = candidate
            break
    assert seed is not None
    result = classify_backup(seed)
    assert result["format"] == BackupFormat.ELECTRUM_SEED_VERSION.value
    assert result["hmac_checked"] is True


def test_slip39_reference_share_validation_threshold_and_deterministic_reconstruction():
    from shamir_mnemonic import generate_mnemonics
    shares = [item for group in generate_mnemonics(1, [(2, 3)], b"\x01" * 16, passphrase=b"TREZOR", iteration_exponent=0) for item in group]
    info = inspect_slip39_shares(shares[:2])
    assert info["recognized"] is True
    assert info["checksum_valid"] is True
    assert info["group_threshold_met"] is True
    first = reconstruct_slip39(shares[:2], "TREZOR")
    second = reconstruct_slip39(shares[:2], "TREZOR")
    assert first["valid"] is True
    assert first["secret_length"] == 16
    assert first["secret_sha256"] == second["secret_sha256"]
    assert first["secret_material"] == "REDACTED"
    assert reconstruct_slip39(shares[:1], "TREZOR")["valid"] is False


def test_slip39_official_reference_vector_and_invalid_checksum():
    official = [
        "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
        "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking",
    ]
    result = reconstruct_slip39(official, "TREZOR")
    assert result["valid"] is True
    assert len(result["secret_sha256"]) == 64
    invalid = official[0].replace("armed", "coding")
    assert inspect_slip39_shares([invalid])["recognized"] is False


def test_descriptor_engine_expands_multipath_and_wsh_sortedmulti():
    xpub = "xpub6FrCS2gWHvogbAX8ipHuBmbPvckXLYs5SfEKq1Lp3tneESUXuNNUw67q6Q6r1xHhmoQtByXS7SXes78nuGckLXWEuRPWNfwBo8Cp5QQLPKy"
    multipath = derive_descriptor_addresses(f"wpkh({xpub}/<0;1>/*)", index_count=2)
    assert multipath["branches"] == 2
    assert len(multipath["addresses"]) == 4
    multisig = derive_descriptor_addresses(f"wsh(sortedmulti(1,{xpub}/0/*,{xpub}/0/*))", index_count=1)
    assert multisig["error"] is None
    assert multisig["addresses"][0]["address"].startswith("bc1")


def test_bip388_and_bsms_public_policy_evidence():
    xpub = "xpub6FrCS2gWHvogbAX8ipHuBmbPvckXLYs5SfEKq1Lp3tneESUXuNNUw67q6Q6r1xHhmoQtByXS7SXes78nuGckLXWEuRPWNfwBo8Cp5QQLPKy"
    policy = {"policy": f"wpkh({xpub}/<0;1>/*)", "keys": [{"origin": "[deadbeef/84h/0h/0h]", "xpub": xpub}]}
    assert inspect_bip388(policy)["recognized"] is True
    bsms = inspect_bsms(f"BSMS 1.0\nMaster Fingerprint: deadbeef\nDerivation: m/48'/0'/0'/2'\n{xpub}")
    assert bsms["recognized"] is True
    assert bsms["master_fingerprints"] == ["deadbeef"]


def test_electrum_artifact_extracts_public_metadata_and_fails_closed_for_encryption():
    xpub = "xpub6FrCS2gWHvogbAX8ipHuBmbPvckXLYs5SfEKq1Lp3tneESUXuNNUw67q6Q6r1xHhmoQtByXS7SXes78nuGckLXWEuRPWNfwBo8Cp5QQLPKy"
    adapter = ElectrumArtifactAdapter()
    plain = {"wallet_type": "standard", "seed_version": 17, "use_change": True, "gap_limit": 20, "keystore": {"xpub": xpub, "derivation": "m/44'/0'/0'"}}
    inspected = adapter.inspect(plain)
    assert inspected.detected is True and inspected.encrypted is False
    assert adapter.verify_password_candidate(plain, "").valid is True
    assert xpub in adapter.extract_public_evidence(plain)["xpubs"]
    encrypted = {**plain, "use_encryption": True}
    result = adapter.verify_password_candidate(encrypted, "owner-password")
    assert result.valid is False
    assert "authentication failed" in result.error
    assert result.secrets_discarded is True


def test_electrum_native_bie1_and_bie2_ecies_password_validation():
    import base64
    import hashlib
    import hmac
    import json
    import zlib
    from coincurve import PrivateKey
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from backend.wallet_recovery.artifact_adapters.electrum import _private_key_from_password

    def fixture(magic):
        password = "native-electrum-password"
        recipient = _private_key_from_password(password)
        ephemeral = PrivateKey()
        shared = recipient.public_key.multiply(ephemeral.secret)
        key = hashlib.sha512(shared.format(compressed=True)).digest()
        plaintext = zlib.compress(json.dumps({"wallet_type": "standard", "keystore": {"xpub": "xpub-public-only"}, "seed": "MUST_NOT_ESCAPE"}).encode())
        ciphertext = AES.new(key[16:32], AES.MODE_CBC, key[:16]).encrypt(pad(plaintext, AES.block_size))
        envelope = magic + ephemeral.public_key.format(compressed=True) + ciphertext
        envelope += hmac.new(key[32:], envelope, hashlib.sha256).digest()
        return base64.b64encode(envelope).decode()

    adapter = ElectrumArtifactAdapter()
    for magic in (b"BIE1", b"BIE2"):
        artifact = fixture(magic)
        assert adapter.inspect(artifact).public_metadata["storage_encryption"] == magic.decode()
        assert adapter.verify_password_candidate(artifact, "wrong").valid is False
        result = adapter.verify_password_candidate(artifact, "native-electrum-password")
        assert result.valid is True
        assert result.public_evidence["xpubs"] == ["xpub-public-only"]
        assert "MUST_NOT_ESCAPE" not in str(result.public_evidence)


def test_bitcoin_core_dump_and_sqlite_paths_are_public_only(tmp_path: Path):
    dump = tmp_path / "wallet.dump"
    dump.write_text("# Wallet dump created by Bitcoin Core\n1BoatSLRHtKNngkdXEeobR76b53LETtpyT 0 label=receive\n", encoding="utf-8")
    adapter = BitcoinCoreArtifactAdapter()
    inspected = adapter.inspect(str(dump))
    assert inspected.detected is True
    assert inspected.public_metadata["wallet_format"] == "dumpwallet"
    assert inspected.public_metadata["known_addresses"] == ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"]
    assert adapter.verify_password_candidate(str(dump), "anything").valid is False


def test_behavior_fingerprint_hypothesis_graph_and_proof_bundle_are_sanitized():
    behavior = build_behavior_fingerprint(wallet_application="Electrum", wallet_type="bitcoin", seed_format="ELECTRUM_SEED_VERSION")
    assert behavior["electrum_semantics"] is True
    graph = RecoveryHypothesisGraph()
    graph.add(HypothesisNode("artifact", "artifact", "electrum-wallet", 0.9, 1))
    graph.add(HypothesisNode("seed", "seed-format", "electrum", 0.8, 2))
    graph.link("artifact", "seed")
    graph.eliminate_subtree("artifact")
    assert graph.ranked() == []
    proof = RecoveryProofBundle()
    proof.add("MASTER_FINGERPRINT_MATCH", "fingerprint matched", decisive=True)
    sanitized = proof.sanitized()
    assert sanitized["cryptographic_certainty"] == "EXACT"
    assert sanitized["secrets"] == "REDACTED"


def test_early_wallet_identification_ranks_electrum_from_owner_evidence(tmp_path: Path):
    artifact = tmp_path / "electrum.wallet"
    artifact.write_text("public metadata placeholder", encoding="utf-8")
    evidence = WalletEvidence(
        known_addresses=["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"],
        network="bitcoin",
        wallet_application="Electrum",
        approximate_creation_date="2015-06-01",
        wallet_artifact_path=str(artifact),
        transaction_dates=["2016-01-01"],
    )
    result = identify_early_wallet(evidence)
    assert result["status"] in {"IDENTIFIED", "LIKELY"}
    assert result["hypotheses"][0]["profile_id"] in {"electrum-legacy", "electrum-modern"}
    assert result["age_is_evidence_only"] is True
    assert result["secrets_persisted"] is False


def test_early_wallet_identification_uses_descriptor_and_xpub_as_public_evidence():
    xpub = "xpub6FrCS2gWHvogbAX8ipHuBmbPvckXLYs5SfEKq1Lp3tneESUXuNNUw67qQ6r1xHhmoQtByXS7SXes78nuGckLXWEuRPWNfwBo8Cp5QQLPKy"
    evidence = WalletEvidence(
        network="bitcoin",
        wallet_application="Bitcoin Core",
        approximate_creation_date="2023-01-01",
        extended_public_key=xpub,
        output_descriptor="wpkh(xpub/0/*)",
    )
    result = identify_early_wallet(evidence)
    assert result["hypotheses"]
    assert result["hypotheses"][0]["profile_id"] == "bitcoin-core-descriptor"
    assert result["evidence_used"]["has_xpub"] is True
    assert result["evidence_used"]["has_descriptor"] is True
