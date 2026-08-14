"""Public-identifier verification; candidate secrets never leave this module."""

from .derivation import derive_one


def normalize_address(network: str, address: str) -> str:
    return address.lower() if network in ("ethereum", "evm", "eth") else address


def verify_mnemonic_address(mnemonic: str, *, network: str, address: str, path: str, passphrase: str = ""):
    derived = derive_one(mnemonic, network=network, path=path, passphrase=passphrase)
    return {"matched": normalize_address(network, derived.address) == normalize_address(network, address), "network": derived.network, "path": derived.path, "address": derived.address}
