"""Structured mnemonic, passphrase, and derivation constraints."""

from itertools import product

from .models import RecoveryConstraintSet


def passphrase_variants(base: str, *, capitalization=False, whitespace=False, normalization=False):
    values = {base}
    if capitalization:
        values.update({base.lower(), base.upper(), base.title()})
    if whitespace:
        values.update({base.strip(), f" {base}", f"{base} "})
    if normalization:
        import unicodedata
        values.update({unicodedata.normalize("NFC", base), unicodedata.normalize("NFKC", base)})
    return sorted(values)


def structured_passphrase_hypotheses(*, components=None, years=None, suffixes=None, separators=None, capitalization=False, whitespace=False, keyboard_variants=False, normalization=False, max_candidates=1000):
    """Build a bounded owner-supplied grammar; never use an external dictionary."""
    components = [str(item) for item in (components or []) if item]
    years = [str(item) for item in (years or []) if str(item).isdigit()]
    suffixes = [str(item) for item in (suffixes or []) if item]
    separators = list(separators or ["", " ", "_", "-", "!"])
    seeds = set(components)
    for component in components:
        for year in years:
            for separator in separators:
                seeds.add(f"{component}{separator}{year}")
        for suffix in suffixes:
            for separator in separators:
                seeds.add(f"{component}{separator}{suffix}")
    variants = []
    for value in seeds:
        variants.extend(passphrase_variants(value, capitalization=capitalization, whitespace=whitespace, normalization=normalization))
        if keyboard_variants:
            variants.extend([value.replace("a", "@"), value.replace("i", "1"), value.replace("e", "3")])
    return list(dict.fromkeys(variants))[:max_candidates]


def restricted_word_space(constraints: RecoveryConstraintSet, wordlist_size=2048):
    count = 1
    for position, values in constraints.restricted_positions.items():
        count *= max(1, min(len(values), wordlist_size))
    count *= wordlist_size ** len(constraints.uncertain_positions)
    return count


def build_constraints(*, mnemonic_length=None, known_positions=None, restricted_positions=None, uncertain_positions=None, passphrase_candidates=None, **kwargs):
    return RecoveryConstraintSet(mnemonic_length=mnemonic_length, known_positions=known_positions or [], restricted_positions=restricted_positions or {}, uncertain_positions=uncertain_positions or [], passphrase_candidates=passphrase_candidates or [], **kwargs)
