"""Checksum-first, position-aware BIP39 candidate generation.

This module only yields valid BIP39 phrases. It never derives keys or performs
network calls, so callers can apply a seed/KDF budget after structural pruning.
"""

from itertools import product
from typing import Iterable

from hdwallet.mnemonics import BIP39Mnemonic


MARKERS = {"?", "_", "unknown", "[unknown]", "<unknown>"}
VALID_LENGTHS = {12, 15, 18, 21, 24}


def parse_word_positions(partial: str, *, length: int | None = None):
    tokens = partial.split() if partial else []
    target_length = length or len(tokens)
    if target_length not in VALID_LENGTHS:
        raise ValueError("BIP39 mnemonic length must be 12, 15, 18, 21, or 24")
    if len(tokens) > target_length:
        raise ValueError("partial mnemonic has more words than its declared length")
    tokens += ["?"] * (target_length - len(tokens))
    return tokens


def _prefix_values(prefix: str, words: list[str]):
    needle = prefix.casefold()
    return [word for word in words if word.startswith(needle)]


def _edit_values(value: str, words: list[str], distance: int):
    if distance <= 0:
        return [value]
    result = []
    for word in words:
        delta = sum(a != b for a, b in zip(value, word)) + abs(len(value) - len(word))
        if delta <= distance:
            result.append(word)
    return result


def candidate_word_sets(partial: str, *, length: int | None = None, word_constraints=None, prefixes=None, edit_distance=0, wordlist=None):
    words = list(wordlist or BIP39Mnemonic.get_words_list_by_language("english"))
    tokens = parse_word_positions(partial, length=length)
    restricted = word_constraints or {}
    prefixes = prefixes or {}
    sets = []
    for position, token in enumerate(tokens):
        if position in restricted:
            values = [word for word in restricted[position] if word in words]
        elif position in prefixes:
            values = _prefix_values(prefixes[position], words)
        elif token.casefold() in MARKERS:
            values = words
        elif token in words:
            values = [token]
        else:
            values = _edit_values(token, words, edit_distance)
        sets.append(list(dict.fromkeys(values)))
    return sets


def estimate_raw_combinations(word_sets: list[list[str]]):
    result = 1
    for values in word_sets:
        result *= len(values)
    return result


def iter_valid_mnemonics(partial: str, *, length: int | None = None, word_constraints=None, prefixes=None, edit_distance=0, allow_adjacent_swaps=False, max_candidates: int | None = None):
    sets = candidate_word_sets(partial, length=length, word_constraints=word_constraints, prefixes=prefixes, edit_distance=edit_distance)
    emitted = set()
    count = 0
    for candidate in product(*sets):
        variants = [candidate]
        if allow_adjacent_swaps:
            variants.extend(tuple(candidate[:i]) + (candidate[i + 1], candidate[i]) + tuple(candidate[i + 2:]) for i in range(len(candidate) - 1))
        for variant in variants:
            phrase = " ".join(variant)
            if phrase in emitted:
                continue
            emitted.add(phrase)
            if BIP39Mnemonic.is_valid(phrase):
                yield phrase
                count += 1
                if max_candidates is not None and count >= max_candidates:
                    return


def count_valid_mnemonics(partial: str, **kwargs):
    return sum(1 for _ in iter_valid_mnemonics(partial, **kwargs))
