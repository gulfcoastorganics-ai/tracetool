"""SLIP-0039 validation and in-memory reconstruction using the reference package."""

from hashlib import sha256

from shamir_mnemonic import MnemonicError, Share, combine_mnemonics, decode_mnemonics


def inspect_slip39_shares(shares):
    if isinstance(shares, str):
        shares = [shares]
    shares = [str(item).strip() for item in shares if str(item).strip()]
    if not shares or any(len(item.split()) not in (20, 33, 59) for item in shares):
        return {"recognized": False, "share_count": len(shares)}
    parsed = []
    try:
        for item in shares:
            parsed.append(Share.from_mnemonic(item))
        groups = decode_mnemonics(shares)
        first = parsed[0]
        complete_groups = {index: len(group) >= group.member_threshold() for index, group in groups.items()}
        return {"recognized": True, "share_count": len(parsed), "word_lengths": sorted({len(item.split()) for item in shares}), "identifier": first.identifier, "iteration_exponent": first.iteration_exponent, "group_threshold": first.group_threshold, "group_count": first.group_count, "groups": {str(index): {"members": len(group), "member_threshold": group.member_threshold(), "complete": complete_groups[index]} for index, group in groups.items()}, "group_threshold_met": sum(complete_groups.values()) >= first.group_threshold, "checksum_valid": True}
    except (MnemonicError, ValueError, TypeError):
        return {"recognized": False, "share_count": len(shares), "checksum_valid": False}


def reconstruct_slip39(shares, passphrase=""):
    """Reconstruct into transient memory and return only a sanitized result."""
    info = inspect_slip39_shares(shares)
    if not info.get("recognized"):
        return {"valid": False, "format": "SLIP39", "error": "Invalid SLIP-0039 share set"}
    if not info.get("group_threshold_met"):
        return {"valid": False, "format": "SLIP39", "error": "Group/member threshold not met", "metadata": info}
    try:
        secret = combine_mnemonics(shares, passphrase=passphrase.encode("ascii"))
        # Do not return or persist secret bytes. The digest is an audit handle,
        # not a recovery secret, and is never used as a wallet key.
        result = {"valid": True, "format": "SLIP39", "secret_length": len(secret), "secret_sha256": sha256(secret).hexdigest(), "metadata": info, "secret_material": "REDACTED", "persisted": False}
        del secret
        return result
    except Exception:
        return {"valid": False, "format": "SLIP39", "error": "SLIP-0039 reconstruction failed", "metadata": info}
