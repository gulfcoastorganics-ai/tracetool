"""Public wallet-policy and BSMS evidence extraction."""

import json
import re

from .descriptors import analyze_descriptor, derive_descriptor_addresses


def inspect_bip388(policy):
    value = json.loads(policy) if isinstance(policy, str) and policy.lstrip().startswith("{") else policy
    if not isinstance(value, dict):
        return {"recognized": False, "format": "BIP388"}
    template = value.get("descriptor_template") or value.get("policy") or value.get("template")
    keys = value.get("keys") or value.get("key_information") or []
    if not template or not isinstance(keys, list):
        return {"recognized": False, "format": "BIP388"}
    public_keys = [item for item in keys if isinstance(item, dict) and any(token in str(item).lower() for token in ("xpub", "ypub", "zpub", "pubkey"))]
    descriptor = template
    return {"recognized": True, "format": "BIP388", "policy_template": template, "key_count": len(keys), "public_key_records": len(public_keys), "origins": [item.get("origin") or item.get("derivation_path") for item in keys if isinstance(item, dict)], "descriptor": analyze_descriptor(descriptor), "addresses": derive_descriptor_addresses(descriptor, index_count=2).get("addresses", [])}


def inspect_bsms(value):
    text = json.dumps(value) if isinstance(value, dict) else str(value or "")
    if not any(marker in text.lower() for marker in ("bsms", "bitcoin secure multisig", "multisig")):
        return {"recognized": False, "format": "BSMS"}
    xpubs = re.findall(r"(?:xpub|ypub|zpub|tpub|upub|vpub)[A-Za-z0-9]+", text)
    fingerprints = re.findall(r"(?i)(?:fingerprint|master_fingerprint)\D*([0-9a-f]{8})", text)
    paths = re.findall(r"m/[0-9h'/]+", text)
    addresses = re.findall(r"(?i)(?:address|first_address)\D*([13bc1q][A-Za-z0-9]{20,})", text)
    return {"recognized": True, "format": "BSMS", "xpub_count": len(set(xpubs)), "xpubs": list(dict.fromkeys(xpubs)), "master_fingerprints": list(dict.fromkeys(fingerprints)), "origin_paths": list(dict.fromkeys(paths)), "known_addresses": list(dict.fromkeys(addresses)), "public_only": True}
