"""Strict BIP39 entropy/checksum validation without persisting secrets."""

import hashlib

from hdwallet.mnemonics import BIP39Mnemonic

from .models import BIP39ValidationResult


def _checksum_bits(entropy_bits: int) -> int:
    return entropy_bits // 32


def validate_bip39_entropy(entropy_hex: str) -> BIP39ValidationResult:
    try:
        raw = bytes.fromhex(entropy_hex)
    except ValueError:
        return BIP39ValidationResult(valid=False, reasons=["entropy is not valid hexadecimal"])
    ent = len(raw) * 8
    if ent not in (128, 160, 192, 224, 256):
        return BIP39ValidationResult(valid=False, reasons=["BIP39 entropy must be 128, 160, 192, 224, or 256 bits"])
    mnemonic = BIP39Mnemonic.from_entropy(raw, "english")
    result = validate_mnemonic(mnemonic)
    # Do not return entropy bytes in ordinary validation responses.
    result.entropy_hex = None
    return result


def validate_mnemonic(mnemonic: str, *, include_entropy: bool = False) -> BIP39ValidationResult:
    words = mnemonic.strip().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return BIP39ValidationResult(valid=False, mnemonic_words=len(words), reasons=["mnemonic must contain a standard BIP39 word count"])
    try:
        valid = BIP39Mnemonic.is_valid(" ".join(words), words_list=BIP39Mnemonic.get_words_list_by_language("english"))
    except Exception:
        valid = False
    ent = ((len(words) * 11) * 32) // 33
    checksum = ent // 32
    reasons = [] if valid else ["word indices or checksum are invalid"]
    entropy_hex = None
    if valid and include_entropy:
        entropy_hex = BIP39Mnemonic.decode(" ".join(words), words_list=BIP39Mnemonic.get_words_list_by_language("english"))
    return BIP39ValidationResult(valid=valid, entropy_bits=ent if valid else None, checksum_bits=checksum if valid else None, mnemonic_words=len(words), entropy_hex=entropy_hex, reasons=reasons)


def validate_256_construction(entropy_hex: str):
    result = validate_bip39_entropy(entropy_hex)
    if result.valid and result.entropy_bits == 256 and result.checksum_bits == 8 and result.mnemonic_words == 24:
        return result
    return BIP39ValidationResult(valid=False, entropy_bits=result.entropy_bits, checksum_bits=result.checksum_bits, mnemonic_words=result.mnemonic_words, reasons=result.reasons or ["256-bit construction requires ENT=256, CS=8, and 24 words"])
