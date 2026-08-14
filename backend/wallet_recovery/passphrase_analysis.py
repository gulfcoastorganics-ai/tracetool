"""Passphrase guidance; never expands arbitrary dictionaries or attacks targets."""


def analyze_passphrase_state(*, known: bool, hints=None):
    hints = hints or []
    if known:
        return {"status": "KNOWN", "candidate_count": 1, "recommendation": "Verify the known passphrase locally against the owner-supplied address."}
    if hints:
        return {"status": "OWNER_HINTS_AVAILABLE", "candidate_count": None, "recommendation": "Use only a small owner-confirmed set of passphrase candidates; no dictionaries or external target search are generated."}
    return {"status": "UNKNOWN", "candidate_count": None, "recommendation": "Treat the passphrase as a configuration branch; do not assume the empty passphrase."}
