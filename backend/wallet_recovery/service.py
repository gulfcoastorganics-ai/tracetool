"""Owner-controlled recovery orchestration."""

from datetime import datetime, timezone
from time import monotonic

from hdwallet.mnemonics import BIP39Mnemonic

from backend.entropy_assurance.bip39_validation import validate_mnemonic

from .candidate_verifier import verify_mnemonic_address
from .candidate_space import estimate_candidate_space
from .derivation import MAX_DERIVATIONS, explore_derivations
from .evidence import owner_control_is_sufficient, summarize_evidence
from .feasibility import classify_evidence, partial_mnemonic_feasibility
from .fingerprint import build_fingerprint
from .extended_keys import derive_extended_key_addresses
from .descriptors import derive_descriptor_addresses
from .recovery_executor import execute_partial_recovery
from .mnemonic_candidates import candidate_word_sets, estimate_raw_combinations
from .constraints import structured_passphrase_hypotheses
from .path_hypotheses import rank_path_hypotheses
from .artifact_adapters import adapter_for, inspect_artifact
from .formats import classify_backup
from .slip39 import inspect_slip39_shares, reconstruct_slip39
from .gap_scanner import discover_extended_key_gap
from .generator_provenance import analyze_generator
from .mnemonic_analysis import analyze_partial_mnemonic
from .models import (
    AddressVerificationRequest, AddressVerificationResult, DerivationExploreRequest, DerivationResult,
    GeneratorAnalysisRequest, MnemonicAnalysisRequest, MnemonicAnalysisResult, RecoveryAnalysisRequest,
    RecoveryAnalysisResult, RecoveryClassification, RecoveryPlanRequest, RecoveryPlanResult,
    RecoveryReport, RecoverySessionRequest, RecoverySessionResponse, RecoveryStatus,
    RecoveryBudget, RecoveryTermination, RecoveryServiceResult,
)
from .recovery_plan import build_plan
from .report import persist_report
from .session import recovery_sessions
from .wallet_profiles import all_profiles, get_profile, profile_matches
from .early_wallet import identify_early_wallet


def _unknown_words(text: str | None, known_positions):
    if not text:
        return 0
    tokens = text.split()
    markers = {"?", "_", "unknown", "[unknown]", "<unknown>"}
    marked = sum(1 for token in tokens if token.lower() in markers)
    return max(marked, len(known_positions) and max(0, len(tokens) - len([token for token in tokens if token.lower() not in markers])) or 0)


class WalletRecoveryService:
    def __init__(self):
        self.history_provider = None

    def configure_history_provider(self, provider):
        """Configure an explicitly local/provider-owned public-only adapter."""
        self.history_provider = provider

    def inspect_artifact(self, artifact):
        return inspect_artifact(artifact)

    def verify_artifact_password(self, artifact, password):
        adapter = adapter_for(artifact)
        if adapter is None:
            raise ValueError("No supported format-specific artifact adapter matched")
        result = adapter.verify_password_candidate(artifact, password)
        return {"adapter_id": adapter.adapter_id, "valid": result.valid, "public_evidence": result.public_evidence, "estimated_work": result.estimated_work, "error": result.error, "secrets_discarded": True}

    def discover_gap(self, request):
        return discover_extended_key_gap(request.extended_public_key, network=request.network, provider=self.history_provider, gap_limit=request.gap_limit, max_index=request.max_index)

    def classify_backup(self, backup):
        return classify_backup(backup)

    def reconstruct_slip39(self, shares, passphrase):
        return reconstruct_slip39(shares, passphrase)

    @staticmethod
    def _assessment(evidence, feasibility, *, matched=False, unique=False):
        private = bool(evidence.complete_mnemonic or evidence.partial_mnemonic or evidence.private_key_available or evidence.extended_private_key)
        public = bool(evidence.known_addresses or evidence.extended_public_key or evidence.output_descriptor or evidence.watch_only_export)
        owner = bool(evidence.known_addresses or private or evidence.wallet_artifact_path or evidence.watch_only_export)
        if matched:
            return {"service_result": RecoveryServiceResult.RECOVERY_CONFIRMED if unique else RecoveryServiceResult.PUBLIC_IDENTIFIER_MATCH, "ownership_evidence": "VERIFIED", "private_evidence": "SUFFICIENT", "public_match_status": "UNIQUE_PUBLIC_MATCH" if unique else "PUBLIC_IDENTIFIER_MATCH"}
        if feasibility.classification == RecoveryClassification.COMPUTATIONALLY_INFEASIBLE:
            result = RecoveryServiceResult.CRYPTOGRAPHICALLY_INFEASIBLE if owner else RecoveryServiceResult.INSUFFICIENT_PRIVATE_EVIDENCE
        elif private and feasibility.expensive_work_allowed:
            result = RecoveryServiceResult.RECOVERY_FEASIBLE
        elif private:
            result = RecoveryServiceResult.PRIVATE_EVIDENCE_SUFFICIENT
        elif feasibility.expensive_work_allowed and public:
            result = RecoveryServiceResult.RECOVERY_FEASIBLE
        else:
            result = RecoveryServiceResult.INSUFFICIENT_PRIVATE_EVIDENCE
        return {"service_result": result, "ownership_evidence": "OWNER_EVIDENCE_PRESENT" if owner else "INSUFFICIENT", "private_evidence": "SUFFICIENT" if private else "INSUFFICIENT", "public_match_status": "PENDING" if public else "UNAVAILABLE"}
    def identify_early_wallet(self, evidence):
        return identify_early_wallet(evidence)
    def capabilities(self):
        return {"enabled": True, "owner_controlled": True, "external_private_key_search": False, "blockchain_queries": False, "offline_mode_default": True, "budget_defaults": RecoveryBudget().model_dump(mode="json"), "supported_networks": ["bitcoin", "ethereum", "solana"], "wallet_profiles": len(all_profiles()), "historical_wallet_profiles": 9, "sensitive_values": "active in-memory session only", "classifications": [item.value for item in RecoveryClassification], "early_wallet_identification": True}

    def analyze(self, request: RecoveryAnalysisRequest):
        evidence = request.evidence
        early_wallet = identify_early_wallet(evidence)
        unknown = _unknown_words(evidence.partial_mnemonic, evidence.known_word_positions)
        feasibility = classify_evidence(evidence, partial_unknown_count=unknown)
        fingerprint = build_fingerprint(evidence)
        profiles = profile_matches(application=evidence.wallet_application, network=evidence.network)
        if evidence.complete_mnemonic:
            space = estimate_candidate_space(mnemonic_length=24, unknown_words=0, profile_count=max(1, len(profiles)), addresses_per_profile=request.requested_index_count, address_evidence=bool(evidence.known_addresses or evidence.extended_public_key or evidence.output_descriptor), budget=request.budget)
        elif evidence.partial_mnemonic:
            word_count = len(evidence.partial_mnemonic.split())
            space = estimate_candidate_space(mnemonic_length=word_count if word_count in (12, 15, 18, 21, 24) else 24, unknown_words=unknown, profile_count=max(1, len(profiles)), addresses_per_profile=request.requested_index_count, address_evidence=bool(evidence.known_addresses or evidence.extended_public_key or evidence.output_descriptor), budget=request.budget)
            try:
                sets = candidate_word_sets(evidence.partial_mnemonic, word_constraints=evidence.mnemonic_word_constraints, prefixes=evidence.mnemonic_prefixes, edit_distance=evidence.max_word_edit_distance)
                raw = estimate_raw_combinations(sets)
                space.candidate_space_before_constraints = raw
                space.candidate_space_after_checksum = max(0, raw // (1 << (len(sets) // 3)))
                space.estimated_derivations = space.candidate_space_after_checksum * max(1, len(profiles)) * request.requested_index_count
                space.budget = (request.budget or RecoveryBudget()).model_dump(mode="json")
            except ValueError:
                pass
        else:
            report = evidence.entropy_assurance_report or {}
            space = estimate_candidate_space(profile_count=max(1, len(profiles)), addresses_per_profile=request.requested_index_count, address_evidence=bool(evidence.known_addresses or evidence.extended_public_key or evidence.output_descriptor), weak_effective_bits=report.get("maximum_effective_bits") if report.get("maximum_effective_bits") is not None else None, budget=request.budget)
        paths = []
        if evidence.complete_mnemonic:
            paths = ["m/44'/0'/0'/0/i", "m/49'/0'/0'/0/i", "m/84'/0'/0'/0/i", "m/86'/0'/0'/0/i", "m/44'/60'/0'/0/i", "m/44'/60'/0'/i", "m/44'/60'/i'/0/0", "m/44'/501'/0'/0'", "m/44'/501'/i'/0'"]
        if feasibility.classification == RecoveryClassification.RECOVERABLE_CONFIGURATION:
            diagnosis = "Secret entropy recovery unnecessary; current evidence points to wallet configuration, passphrase, or derivation mismatch."
            path = "bounded derivation explorer"
        elif feasibility.classification == RecoveryClassification.RECOVERABLE_KNOWN_WEAK_GENERATOR:
            diagnosis = "Effective search domain is reduced by documented generator provenance and entropy evidence."
            path = "generator-specific bounded verifier"
        else:
            diagnosis = feasibility.explanation
            path = "evidence gathering and feasibility review"
        hypotheses = rank_path_hypotheses(network=evidence.network or "bitcoin", wallet_application=evidence.wallet_application, creation_year=fingerprint.creation_year, address_types=fingerprint.address_types, extended_key_type=fingerprint.extended_key_type, descriptor=evidence.output_descriptor, known_path=evidence.known_derivation_path)
        backup = classify_backup(evidence.complete_mnemonic or evidence.partial_mnemonic or "")
        assessment = self._assessment(evidence, feasibility)
        return RecoveryAnalysisResult(classification=feasibility.classification, feasibility=feasibility, evidence_summary=summarize_evidence(evidence), diagnosis=diagnosis, recommended_path=path, derivation_paths_to_try=paths, wallet_fingerprint=fingerprint.model_dump(mode="json"), matched_profiles=[profile.model_dump(mode="json") for profile in profiles], candidate_space=space.model_dump(mode="json"), path_hypotheses=[item.__dict__ for item in hypotheses], backup_format=backup, early_wallet_identification=early_wallet, **assessment)

    def create_session(self, request: RecoverySessionRequest):
        if not owner_control_is_sufficient(request.evidence):
            raise ValueError("An owner-supplied address or secret/configuration artifact is required to create a recovery session")
        token = recovery_sessions.create(request.evidence, request.ttl_seconds)
        return RecoverySessionResponse(session_token=token, expires_in_seconds=request.ttl_seconds)

    def derive(self, request: DerivationExploreRequest):
        evidence = recovery_sessions.get(request.session_token)
        mnemonic = evidence.complete_mnemonic
        if not mnemonic and evidence.partial_mnemonic:
            result = execute_partial_recovery(evidence, budget=request.budget, networks=request.networks, passphrases=[request.passphrase] if request.passphrase is not None else None, history_provider=self.history_provider, resume_candidate_offset=request.resume_candidate_offset)
            identifiers = [{"network": item["network"], "path": item["path"], "address": item["address"], "matched": True} for item in result.get("matches", [])]
            matched = bool(identifiers)
            public_keys = {(item.get("network"), str(item.get("address", "")).lower()) for item in identifiers}
            assessment = self._assessment(evidence, classify_evidence(evidence), matched=matched, unique=matched and len(public_keys) == 1 and result.get("termination") == RecoveryTermination.UNIQUE_PUBLIC_MATCH)
            return DerivationResult(status=RecoveryStatus.MATCH if matched else (RecoveryStatus.BLOCKED if result.get("status") == "BLOCKED" else RecoveryStatus.NO_MATCH), identifiers=identifiers, matches=identifiers, derivations_attempted=result.get("preflight", {}).get("actual_full_derivations", 0), checkpoint=result.get("checkpoint"), termination=result.get("termination"), preflight=result.get("preflight"), candidate_provenance=result.get("candidate_provenance", []), **assessment)
        if not mnemonic:
            raise ValueError("Derivation explorer requires a complete mnemonic in the active owner session")
        validation = validate_mnemonic(mnemonic)
        if not validation.valid:
            raise ValueError("Owner-supplied mnemonic failed BIP39 validation")
        budget = request.budget or RecoveryBudget()
        if request.passphrase is not None:
            passphrases = [request.passphrase]
        elif evidence.passphrase_components or evidence.passphrase_years or evidence.passphrase_suffixes:
            passphrases = structured_passphrase_hypotheses(components=evidence.passphrase_components, years=evidence.passphrase_years, suffixes=evidence.passphrase_suffixes, separators=evidence.passphrase_separators or None, capitalization=evidence.passphrase_capitalization_variants, whitespace=evidence.passphrase_whitespace_variants, keyboard_variants=evidence.passphrase_keyboard_variants, normalization=evidence.passphrase_normalization_variants, max_candidates=budget.max_seed_candidates)
        else:
            passphrases = evidence.passphrase_hints if evidence.passphrase_known and evidence.passphrase_hints else [""]
        if len(passphrases) > min(budget.max_seed_candidates, budget.max_pbkdf2_operations):
            raise ValueError("passphrase candidates exceed the active recovery budget")
        requested_paths = request.account_count * request.index_count * 7
        if requested_paths > min(budget.max_paths_per_seed, budget.max_child_derivations):
            raise ValueError("path expansion exceeds the active recovery budget")
        selected_profiles = [get_profile(profile_id) for profile_id in request.profile_ids if get_profile(profile_id)]
        bitcoin_purposes = sorted({purpose for profile in selected_profiles for purpose in profile.purposes}) or None
        constraint_addresses = set(evidence.known_addresses)
        if evidence.extended_public_key:
            constraint_addresses.update(item["address"] for item in derive_extended_key_addresses(evidence.extended_public_key, index_count=request.index_count).get("addresses", []))
        if evidence.output_descriptor:
            constraint_addresses.update(item["address"] for item in derive_descriptor_addresses(evidence.output_descriptor, index_count=request.index_count).get("addresses", []))
        known = {(network, address.lower() if network == "ethereum" else address) for network in request.networks for address in constraint_addresses}
        candidates = []
        started = monotonic()
        pbkdf2_count = 0
        for passphrase in passphrases[:budget.max_seed_candidates]:
            if monotonic() - started > budget.max_runtime_seconds:
                raise ValueError("recovery runtime budget exceeded before completion")
            candidates.extend(explore_derivations(mnemonic, networks=request.networks, passphrase=passphrase, account_start=request.account_start, account_count=request.account_count, index_start=request.index_start, index_count=request.index_count, bitcoin_purposes=bitcoin_purposes))
            pbkdf2_count += 1
            if any((candidate.network, candidate.address.lower() if candidate.network == "ethereum" else candidate.address) in known for candidate in candidates):
                break
        identifiers = []
        for candidate in candidates:
            key = (candidate.network, candidate.address.lower() if candidate.network == "ethereum" else candidate.address)
            identifiers.append({"network": candidate.network, "path": candidate.path, "address": candidate.address, "matched": key in known})
        matches = [item for item in identifiers if item["matched"]]
        matched_public_keys = {(item["network"], item["address"].lower()) for item in matches}
        assessment = self._assessment(evidence, classify_evidence(evidence), matched=bool(matches), unique=len(matched_public_keys) == 1)
        if not matches and not passphrases:
            assessment["service_result"] = RecoveryServiceResult.INSUFFICIENT_PRIVATE_EVIDENCE
        return DerivationResult(status=RecoveryStatus.MATCH if matches else RecoveryStatus.NO_MATCH, identifiers=identifiers, matches=matches, derivations_attempted=len(identifiers), checkpoint={"profiles_examined": len(profile_matches(application=evidence.wallet_application, network=evidence.network)), "ranges_completed": 1, "candidate_count": len(identifiers), "pbkdf2_operations": pbkdf2_count, "child_derivations": len(identifiers), "secrets_persisted": False, "budget": budget.model_dump(mode="json")}, **assessment)

    def verify_address(self, request: AddressVerificationRequest):
        evidence = recovery_sessions.get(request.session_token)
        if not evidence.complete_mnemonic:
            raise ValueError("Address verification requires a complete mnemonic in the active owner session")
        passphrase = request.passphrase or ""
        result = verify_mnemonic_address(evidence.complete_mnemonic, network=request.network, address=request.address, path=request.derivation_path or evidence.known_derivation_path or "m/44'/60'/0'/0/0", passphrase=passphrase)
        status = RecoveryStatus.MATCH if result["matched"] else RecoveryStatus.NO_MATCH
        report = RecoveryReport(classification=RecoveryClassification.RECOVERABLE_CONFIGURATION, diagnosis="Owner-supplied secret matched a known public identifier." if result["matched"] else "Derived public identifier did not match the supplied address.", recovery_basis="BIP39 mnemonic and derivation configuration", verification_status=status, network=result["network"], matched_address=result["address"] if result["matched"] else None, derivation_path=result["path"], created_at=datetime.now(timezone.utc).isoformat())
        if result["matched"]:
            persist_report(report)
        return AddressVerificationResult(status=status, network=result["network"], address=result["address"], derivation_path=result["path"], recovery_basis="BIP39 mnemonic and derivation configuration", service_result=RecoveryServiceResult.RECOVERY_CONFIRMED if result["matched"] else RecoveryServiceResult.VALID_RECOVERY_CANDIDATE, public_match_status="UNIQUE_PUBLIC_MATCH" if result["matched"] else "NO_MATCH")

    def analyze_mnemonic(self, request: MnemonicAnalysisRequest):
        if request.partial_mnemonic:
            known = request.known_word_count if request.known_word_count is not None else len([word for word in request.partial_mnemonic.split() if word not in {"?", "_", "unknown", "[unknown]", "<unknown>"}])
        else:
            known = request.known_word_count or 0
        return MnemonicAnalysisResult(**analyze_partial_mnemonic(mnemonic_length=request.mnemonic_length, known_word_count=known, known_positions=request.known_word_positions, address_available=request.expected_address_available))

    def analyze_generator(self, request):
        return analyze_generator(request)

    def build_plan(self, request: RecoveryPlanRequest):
        analysis = self.analyze(request)
        return build_plan(request.evidence, analysis.classification)


wallet_recovery_service = WalletRecoveryService()
