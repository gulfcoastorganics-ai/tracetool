"""Bounded address/change gap scanning over selected profiles."""

from .derivation import explore_derivations
from .extended_keys import derive_extended_key_addresses


def scan_gap(mnemonic: str, *, networks, passphrase="", account_start=0, account_count=1, index_start=0, gap_limit=20, scan_change=True):
    # The underlying explorer is bounded; this scanner exposes the same public-only result.
    index_count = min(gap_limit, 50)
    return explore_derivations(mnemonic, networks=networks, passphrase=passphrase, account_start=account_start, account_count=account_count, index_start=index_start, index_count=index_count)


def discover_extended_key_gap(extended_public_key: str, *, network="bitcoin", provider=None, gap_limit=20, max_index=1000):
    """Discover bounded external/change addresses after an account xpub match."""
    if provider is None:
        return {"status": "CHAIN_EVIDENCE_UNAVAILABLE", "addresses": [], "queries": 0}
    found = []
    queries = 0
    for branch in (0, 1):
        unused = 0
        for index in range(min(max_index, 1000)):
            derived = derive_extended_key_addresses(extended_public_key, branches=(branch,), index_start=index, index_count=1).get("addresses", [])
            if not derived:
                break
            item = derived[0]
            used = bool(provider.address_used(network, item["address"]))
            queries += 1
            found.append({**item, "branch": branch, "used": used})
            if used:
                unused = 0
            else:
                unused += 1
                if unused >= gap_limit:
                    break
    return {"status": "COMPLETE", "addresses": found, "queries": queries, "gap_limit": gap_limit}
