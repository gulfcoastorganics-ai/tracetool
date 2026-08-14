"""Evidence-weighted candidate ranking."""


def rank_candidate(candidate: dict, *, known_addresses=None, xpub_match=False, transaction_match=False, profile_match=False, path_plausibility=0.0, creation_plausibility=0.0):
    known_addresses = {value.lower() for value in (known_addresses or [])}
    address = str(candidate.get("address", ""))
    score = 0.0
    reasons = []
    if address.lower() in known_addresses:
        score += 1000
        reasons.append("known address match")
    if xpub_match:
        score += 800
        reasons.append("extended public key match")
    if transaction_match:
        score += 500
        reasons.append("transaction history match")
    if profile_match:
        score += 100
        reasons.append("wallet profile match")
    score += path_plausibility * 10 + creation_plausibility * 10
    return {"candidate": candidate, "score": score, "reasons": reasons}


def rank_candidates(candidates, **kwargs):
    return sorted((rank_candidate(candidate, **kwargs) for candidate in candidates), key=lambda item: item["score"], reverse=True)
