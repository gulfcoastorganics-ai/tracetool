"""Automatic recovery-backup format classification."""

from enum import Enum
import unicodedata

from hdwallet.mnemonics import BIP39Mnemonic

from .electrum import detect_electrum_seed
from .slip39 import inspect_slip39_shares


class BackupFormat(str, Enum):
    BIP39 = "BIP39"
    ELECTRUM_SEED_VERSION = "ELECTRUM_SEED_VERSION"
    SLIP39 = "SLIP39"
    UNKNOWN = "UNKNOWN"


def classify_backup(value):
    if isinstance(value, str):
        text = unicodedata.normalize("NFKD", value).strip()
        words = text.split()
        electrum = detect_electrum_seed(text)
        if electrum["recognized"]:
            return {"format": BackupFormat.ELECTRUM_SEED_VERSION.value, **electrum}
        slip = inspect_slip39_shares(words)
        if slip["recognized"]:
            return {"format": BackupFormat.SLIP39.value, **slip}
        if BIP39Mnemonic.is_valid(text):
            return {"format": BackupFormat.BIP39.value, "recognized": True, "word_count": len(words), "normalization": "NFKD"}
        return {"format": BackupFormat.UNKNOWN.value, "recognized": False, "word_count": len(words)}
    if isinstance(value, (list, tuple)):
        slip = inspect_slip39_shares(list(value))
        return {"format": BackupFormat.SLIP39.value if slip["recognized"] else BackupFormat.UNKNOWN.value, **slip}
    return {"format": BackupFormat.UNKNOWN.value, "recognized": False}
