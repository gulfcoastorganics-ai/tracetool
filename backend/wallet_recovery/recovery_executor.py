"""Bounded public-identifier recovery execution and non-secret checkpoints."""

from time import monotonic
from hashlib import sha256
import json

from .candidate_ranker import rank_candidates
from .gap_scanner import scan_gap
from .derivation import derive_one, explore_derivations
from .extended_keys import derive_extended_key_addresses
from .descriptors import derive_descriptor_addresses
from .mnemonic_candidates import candidate_word_sets, estimate_raw_combinations, iter_valid_mnemonics
from .models import RecoveryBudget, RecoveryTermination
from .chain_verifier import verify_public_history
from .constraints import structured_passphrase_hypotheses


def execute_bounded_derivation(mnemonic: str, *, networks, passphrase="", known_addresses=None, account_start=0, account_count=1, index_start=0, gap_limit=20, scan_change=True):
    candidates = scan_gap(mnemonic, networks=networks, passphrase=passphrase, account_start=account_start, account_count=account_count, index_start=index_start, gap_limit=gap_limit, scan_change=scan_change)
    public = [{"network": item.network, "path": item.path, "address": item.address} for item in candidates]
    ranked = rank_candidates(public, known_addresses=known_addresses)
    matches = [item for item in ranked if item["score"] >= 1000]
    return {"status": "MATCH" if matches else "NO_MATCH", "candidates": [item["candidate"] for item in ranked], "matches": [item["candidate"] for item in matches], "checkpoint": {"profiles_examined": len(networks), "ranges_completed": 1, "candidate_count": len(public), "secrets_persisted": False}}


def _public_constraints(evidence, *, index_count=20):
    addresses = set(evidence.known_addresses)
    if evidence.extended_public_key:
        addresses.update(item["address"] for item in derive_extended_key_addresses(evidence.extended_public_key, index_count=index_count).get("addresses", []))
    if evidence.output_descriptor:
        addresses.update(item["address"] for item in derive_descriptor_addresses(evidence.output_descriptor, index_count=index_count).get("addresses", []))
    return addresses


def _priority_paths(evidence, networks):
    if evidence.known_derivation_path:
        return [(evidence.network or networks[0], evidence.known_derivation_path)]
    paths = []
    for network in networks:
        if network in ("ethereum", "evm", "eth"):
            paths.append(("ethereum", "m/44'/60'/0'/0/0"))
        elif network in ("bitcoin", "btc"):
            paths.extend(("bitcoin", f"m/{purpose}'/0'/0'/0/0") for purpose in (84, 44, 49, 86))
        elif network == "solana":
            paths.append(("solana", "m/44'/501'/0'/0'"))
    return paths


def execute_partial_recovery(evidence, *, budget=None, networks=None, passphrases=None, word_length=None, history_provider=None, resume_candidate_offset=0):
    """Run checksum-first, budgeted, two-stage recovery for an owner session."""
    budget = budget or RecoveryBudget()
    networks = networks or ([evidence.network] if evidence.network else ["bitcoin", "ethereum", "solana"])
    partial = evidence.partial_mnemonic or ""
    search_plan_hash = sha256(json.dumps({"format": "mnemonic", "networks": networks, "word_constraints": evidence.mnemonic_word_constraints, "prefixes": evidence.mnemonic_prefixes, "edit_distance": evidence.max_word_edit_distance, "swap": evidence.allow_adjacent_word_swaps, "budget": budget.model_dump(mode="json")}, sort_keys=True).encode()).hexdigest()
    word_sets = candidate_word_sets(partial, length=word_length, word_constraints=evidence.mnemonic_word_constraints, prefixes=evidence.mnemonic_prefixes, edit_distance=evidence.max_word_edit_distance)
    raw = estimate_raw_combinations(word_sets)
    # For preflight, checksum reduces the unconstrained population by CS bits;
    # actual execution always validates each generated phrase.
    length = len(word_sets)
    checksum_bits = length // 3
    checksum_estimate = max(0, raw // (1 << checksum_bits))
    preflight = {"raw_combinations": raw, "checksum_valid_estimate": checksum_estimate, "seed_candidates_allowed": budget.max_seed_candidates, "estimated_pbkdf2_operations": min(checksum_estimate, budget.max_pbkdf2_operations), "expected_early_reject_rate": 0.998 if (evidence.known_addresses or evidence.extended_public_key or evidence.output_descriptor) else 0.0, "expected_full_derivations": min(checksum_estimate, budget.max_seed_candidates), "projected_chain_queries": min(budget.max_chain_queries, len(evidence.known_addresses)), "status": "PARTIAL SEARCH — budget limited" if checksum_estimate > budget.max_seed_candidates else "BOUNDED SEARCH"}
    if checksum_estimate == 0:
        return {"status": "NO_MATCH", "termination": RecoveryTermination.NO_CHECKSUM_VALID_CANDIDATES.value, "preflight": preflight, "candidates": [], "matches": [], "candidate_provenance": [], "checkpoint": {"search_plan_hash": search_plan_hash, "format": "BIP39_CANDIDATE_STREAM", "stage": "CHECKSUM", "secrets_persisted": False}}
    constraints = _public_constraints(evidence, index_count=min(100, budget.max_paths_per_seed))
    if not constraints:
        return {"status": "BLOCKED", "termination": RecoveryTermination.COMPUTATIONALLY_INFEASIBLE.value, "preflight": preflight, "candidates": [], "matches": [], "candidate_provenance": [], "checkpoint": {"search_plan_hash": search_plan_hash, "format": "BIP39_CANDIDATE_STREAM", "stage": "PUBLIC_CONSTRAINT", "secrets_persisted": False}}
    if passphrases is not None:
        passphrases = list(passphrases)
    elif evidence.passphrase_components or evidence.passphrase_years or evidence.passphrase_suffixes:
        passphrases = structured_passphrase_hypotheses(components=evidence.passphrase_components, years=evidence.passphrase_years, suffixes=evidence.passphrase_suffixes, separators=evidence.passphrase_separators or None, capitalization=evidence.passphrase_capitalization_variants, whitespace=evidence.passphrase_whitespace_variants, keyboard_variants=evidence.passphrase_keyboard_variants, normalization=evidence.passphrase_normalization_variants, max_candidates=budget.max_seed_candidates)
    else:
        passphrases = list(evidence.passphrase_hints or [""])
    if len(passphrases) > budget.max_seed_candidates:
        return {"status": "BLOCKED", "termination": RecoveryTermination.PASSPHRASE_SPACE_TOO_LARGE.value, "preflight": preflight, "candidates": [], "matches": [], "candidate_provenance": [], "checkpoint": {"search_plan_hash": search_plan_hash, "format": "BIP39_CANDIDATE_STREAM", "stage": "PASSPHRASE_KDF", "secrets_persisted": False}}
    priority = _priority_paths(evidence, networks)
    started = monotonic()
    valid_count = pbkdf2_count = early_rejects = full_derivations = 0
    surviving = []
    for mnemonic in iter_valid_mnemonics(partial, length=word_length, word_constraints=evidence.mnemonic_word_constraints, prefixes=evidence.mnemonic_prefixes, edit_distance=evidence.max_word_edit_distance, allow_adjacent_swaps=evidence.allow_adjacent_word_swaps, max_candidates=budget.max_seed_candidates + resume_candidate_offset):
        if monotonic() - started > budget.max_runtime_seconds:
            break
        valid_count += 1
        if valid_count <= resume_candidate_offset:
            continue
        for passphrase in passphrases:
            if pbkdf2_count >= budget.max_pbkdf2_operations:
                break
            pbkdf2_count += 1
            stage1_match = None
            for network, path in priority[:budget.max_paths_per_seed]:
                try:
                    candidate = derive_one(mnemonic, network=network, path=path, passphrase=passphrase)
                except Exception:
                    continue
                if candidate.address.lower() in {value.lower() for value in constraints}:
                    stage1_match = candidate
                    break
            if stage1_match is None:
                early_rejects += 1
                continue
            surviving.append({"network": stage1_match.network, "path": stage1_match.path, "address": stage1_match.address})
            # Stage 2 expands only candidates that pass the cheap check.
            stage2_index_count = min(20, max(1, budget.max_child_derivations // max(1, len(networks) * 4)))
            expanded = explore_derivations(mnemonic, networks=networks, passphrase=passphrase, index_count=stage2_index_count)[:budget.max_child_derivations]
            full_derivations += len(expanded)
            for item in expanded:
                if item.address.lower() in {value.lower() for value in constraints}:
                    surviving.append({"network": item.network, "path": item.path, "address": item.address})
            if surviving:
                break
        if surviving:
            break
    unique = {(item["network"], item["address"].lower()): item for item in surviving}
    matches = list(unique.values())
    history = {"enabled": False, "offline": True, "checked": 0, "history": {}}
    if matches and evidence.chain_history_verification:
        history = verify_public_history([item["address"] for item in matches], network=evidence.network or networks[0], enabled=True, provider=history_provider, max_queries=budget.max_chain_queries)
        preflight["actual_chain_queries"] = history.get("checked", 0)
        if not history.get("enabled"):
            termination = RecoveryTermination.CHAIN_EVIDENCE_UNAVAILABLE.value
            status = "BLOCKED"
        else:
            used = [item for item in matches if history.get("history", {}).get(item["address"], {}).get("used")]
            if len(used) == 1:
                matches = used
                termination = RecoveryTermination.UNIQUE_PUBLIC_MATCH.value
                status = "MATCH"
            elif len(used) > 1:
                termination = RecoveryTermination.MULTIPLE_PLAUSIBLE_CANDIDATES.value
                status = "MATCH"
            else:
                termination = RecoveryTermination.LOCAL_MATCH_REQUIRES_HISTORY_DISAMBIGUATION.value
                status = "BLOCKED"
    elif len(matches) == 1:
        termination = RecoveryTermination.UNIQUE_PUBLIC_MATCH.value
        status = "MATCH"
    elif len(matches) > 1:
        termination = RecoveryTermination.MULTIPLE_PLAUSIBLE_CANDIDATES.value
        status = "MATCH"
    elif valid_count == 0:
        termination = RecoveryTermination.NO_CHECKSUM_VALID_CANDIDATES.value
        status = "NO_MATCH"
    elif pbkdf2_count >= budget.max_pbkdf2_operations or monotonic() - started > budget.max_runtime_seconds:
        termination = RecoveryTermination.BUDGET_EXHAUSTED.value
        status = "BLOCKED"
    else:
        termination = RecoveryTermination.PUBLIC_CONSTRAINT_MISMATCH.value
        status = "NO_MATCH"
    provenance = [{"candidate_id": f"R-{index + 1:04d}", "confidence": 1.0, "match_certainty": "CRYPTOGRAPHIC_PUBLIC_MATCH", "reasons": ["BIP39 checksum valid", "public constraint matched"], "secret": "REDACTED"} for index, item in enumerate(matches)]
    preflight["actual_valid_candidates"] = valid_count
    preflight["actual_pbkdf2_operations"] = pbkdf2_count
    preflight["early_rejects"] = early_rejects
    preflight["actual_full_derivations"] = full_derivations
    preflight["chain_history"] = history
    return {"status": status, "termination": termination, "preflight": preflight, "candidates": matches, "matches": matches, "candidate_provenance": provenance, "checkpoint": {"search_plan_hash": search_plan_hash, "format": "BIP39_CANDIDATE_STREAM", "stage": "PUBLIC_CONSTRAINT" if matches else "PASSPHRASE_KDF", "valid_candidates": valid_count, "pbkdf2_operations": pbkdf2_count, "early_rejects": early_rejects, "full_derivations": full_derivations, "next_candidate_offset": valid_count, "secrets_persisted": False}}
