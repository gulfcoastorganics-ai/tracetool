"""Defensive, category-level vulnerability profiles.

Profiles intentionally avoid unsourced product/version claims. Named cases can be
added later with primary references and reviewed version boundaries.
"""

from .models import AffectedVersionRange, EntropySource, VulnerabilityProfile, WeaknessClass

PROFILES = [
    VulnerabilityProfile(id="category-weak-browser-wasm-prng", name="Weak browser/WASM randomness", wallet_or_tool="Unspecified browser/WASM wallet", affected_platform="Browser / WASM", affected_versions=AffectedVersionRange(affected_period="environment-dependent"), weakness_class=WeaknessClass.WEAK_BROWSER_WASM_PRNG, entropy_source=EntropySource.WEAK_PRNG, effective_entropy_description="Depends on the browser or WASM fallback; cannot be quantified from mnemonic text alone.", references=["https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues"], notes=["Use implementation evidence; browser context alone is not proof of weakness."], confidence=0.65),
    VulnerabilityProfile(id="category-low-width-seed", name="Low-width PRNG initialization", wallet_or_tool="Unspecified generator", affected_platform="Any", affected_versions=AffectedVersionRange(affected_period="implementation-dependent"), weakness_class=WeaknessClass.LOW_WIDTH_SEED, entropy_source=EntropySource.WEAK_PRNG, effective_entropy_description="Effective entropy is bounded by the disclosed seed/state width.", references=[], notes=["A 32-bit state is not equivalent to 256-bit wallet entropy."], confidence=0.85, known_state_width_bits=32),
    VulnerabilityProfile(id="category-timestamp-seeded", name="Timestamp-seeded generator", wallet_or_tool="Unspecified generator", affected_platform="Any", affected_versions=AffectedVersionRange(affected_period="implementation-dependent"), weakness_class=WeaknessClass.TIMESTAMP_SEEDED, entropy_source=EntropySource.TIMESTAMP, effective_entropy_description="Effective entropy is bounded by the plausible timestamp window and any other state.", references=[], notes=["A creation date narrows a search only when the generator behavior is established."], confidence=0.85),
    VulnerabilityProfile(id="category-math-random", name="Math.random-style generation", wallet_or_tool="Unspecified JavaScript generator", affected_platform="Browser / JavaScript", affected_versions=AffectedVersionRange(affected_period="implementation-dependent"), weakness_class=WeaknessClass.MATH_RANDOM, entropy_source=EntropySource.WEAK_PRNG, effective_entropy_description="Not a cryptographic source; state and implementation determine the actual bound.", references=["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random"], notes=["Passing statistical tests does not establish cryptographic security."], confidence=0.8),
    VulnerabilityProfile(id="category-deterministic-fallback", name="Deterministic RNG fallback", wallet_or_tool="Unspecified generator", affected_platform="Any", affected_versions=AffectedVersionRange(affected_period="implementation-dependent"), weakness_class=WeaknessClass.DETERMINISTIC_FALLBACK, entropy_source=EntropySource.DETERMINISTIC, effective_entropy_description="Effective entropy follows the fallback input, which may be zero or otherwise predictable.", references=[], notes=["A silent fallback after RNG failure is a high-severity design defect."], confidence=0.9),
    VulnerabilityProfile(id="category-brainwallet", name="Brainwallet / human-generated secret", wallet_or_tool="Human-chosen phrase", affected_platform="Any", affected_versions=AffectedVersionRange(affected_period="not software-specific"), weakness_class=WeaknessClass.BRAINWALLET, entropy_source=EntropySource.HUMAN_CHOSEN, effective_entropy_description="Human choice is generally far below the apparent length of the phrase.", references=[], notes=["Do not infer this from unusual-looking words alone."], confidence=0.9),
]


def all_profiles():
    return list(PROFILES)


def get_profile(profile_id: str):
    return next((profile for profile in PROFILES if profile.id == profile_id), None)
