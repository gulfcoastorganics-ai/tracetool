"""Evidence-based matching of wallet provenance to defensive profiles."""

from typing import List, Optional

from .models import EntropySource, GeneratorEvidence, WalletProvenance, VulnerabilityProfile
from .profiles import all_profiles


def match_profiles(provenance: WalletProvenance, evidence: List[GeneratorEvidence] | None = None):
    evidence = evidence or []
    text = " ".join(filter(None, [provenance.generator_details, provenance.rng_function, provenance.source_code_evidence, provenance.implementation_fingerprint] + [item.statement for item in evidence])).lower()
    matches: list[tuple[int, VulnerabilityProfile, list[str]]] = []
    for profile in all_profiles():
        score = 0
        reasons: list[str] = []
        terms = {
            "category-math-random": ("math.random", "random()", "math random"),
            "category-low-width-seed": ("32-bit", "16-bit", "20-bit", "24-bit", "low-width", "mt19937", "mersenne"),
            "category-timestamp-seeded": ("timestamp", "time seed", "date seed"),
            "category-deterministic-fallback": ("fallback", "fixed seed", "deterministic"),
            "category-weak-browser-wasm-prng": ("wasm", "browser", "weak prng"),
            "category-brainwallet": ("brainwallet", "human chosen", "passphrase phrase"),
        }.get(profile.id, ())
        for term in terms:
            if term in text:
                score += 2
                reasons.append(f"evidence mentions {term}")
        if provenance.prng_state_width_bits and profile.id == "category-low-width-seed":
            score += 3
            reasons.append(f"state width disclosed as {provenance.prng_state_width_bits} bits")
        if score:
            matches.append((score, profile, reasons))
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches
