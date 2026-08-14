"""Redaction helpers for wallet recovery responses, reports, and exceptions."""

import re

SENSITIVE = re.compile(r"(mnemonic|seed(?:_phrase)?|private[_-]?key|secret|entropy(?:_bytes)?|passphrase|xprv)", re.I)


def redact(value):
    if isinstance(value, dict):
        return {key: "REDACTED" if SENSITIVE.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def safe_error(exc: Exception):
    return "Recovery operation failed; sensitive values were not included in the error."
