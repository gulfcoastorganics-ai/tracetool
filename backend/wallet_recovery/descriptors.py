"""Safe output-descriptor metadata parsing; no private material is expanded."""

import re


def analyze_descriptor(descriptor: str | None):
    if not descriptor:
        return {"present": False, "script_types": [], "origin_paths": [], "public_only": True}
    lowered = descriptor.lower()
    scripts = re.findall(r"(sortedmulti|multi|wpkh|pkh|sh\(wpkh|tr|wsh)", lowered)
    paths = re.findall(r"m/[0-9'/]+", descriptor)
    threshold = None
    multi_match = re.search(r"(?:sortedmulti|multi)\((\d+)\s*,", lowered)
    if multi_match:
        threshold = int(multi_match.group(1))
    return {"present": True, "script_types": sorted(set(scripts)), "origin_paths": paths[:8], "public_only": "xprv" not in lowered, "policy_type": "multisig" if multi_match else (scripts[0] if scripts else "unknown"), "multisig_threshold": threshold, "key_expression_count": len(re.findall(r"(?:xpub|ypub|zpub|tpub|upub|vpub)", lowered))}


def derive_descriptor_addresses(descriptor: str | None, *, index_start=0, index_count=20):
    """Expand common single-key public descriptors locally.

    This intentionally supports the useful watch-only subset. Multisig,
    ranged key expressions with multiple signers, and private descriptors are
    reported as unsupported rather than guessed.
    """
    info = analyze_descriptor(descriptor)
    if not info["present"] or not info["public_only"]:
        return {**info, "addresses": [], "error": "A public descriptor is required"}
    script_set = set(info["script_types"])
    allowed = script_set <= {"wsh", "multi"} or script_set <= {"wsh", "sortedmulti"} or len(script_set) == 1
    if not allowed:
        return {**info, "addresses": [], "error": "Descriptor contains multiple unsupported policy layers"}
    try:
        from embit.descriptor import Descriptor
        parsed = Descriptor.from_string(descriptor)
        addresses = []
        for branch in range(parsed.num_branches or 1):
            for index in range(index_start, index_start + min(index_count, 100)):
                derived = parsed.derive(index, branch)
                addresses.append({"path": f"branch={branch}/{index}", "address": derived.address(), "script_pubkey": derived.script_pubkey().serialize().hex()})
        return {**info, "addresses": addresses, "branches": parsed.num_branches or 1, "descriptor_engine": "embit", "error": None}
    except Exception as exc:
        return {**info, "addresses": [], "error": "Descriptor expansion failed locally", "detail": type(exc).__name__}
