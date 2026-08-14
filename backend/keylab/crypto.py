"""Bitcoin key/address primitives using libsecp256k1 via coincurve.

No elliptic-curve arithmetic is implemented here. All scalar multiplication
is delegated to coincurve/libsecp256k1. The bitcoinlib engine is a reference
adapter used only for correctness comparisons and never touches the network.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Callable, Dict, Tuple

from coincurve import PrivateKey

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def base58check(version: bytes, payload: bytes) -> str:
    raw = version + payload
    raw += sha256(sha256(raw))[:4]
    number = int.from_bytes(raw, "big")
    encoded = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(_B58_ALPHABET[remainder])
    leading = len(raw) - len(raw.lstrip(b"\0"))
    return (b"1" * leading + bytes(reversed(encoded or b"0"))).decode()


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= generator[index]
    return checksum


def _bech32_hrp_expand(hrp):
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _convertbits(data, from_bits, to_bits, pad=True):
    accumulator = 0
    bits = 0
    output = []
    max_value = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("invalid bit conversion value")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            output.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            output.append((accumulator << (to_bits - bits)) & max_value)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & max_value):
        raise ValueError("invalid unpadded bit conversion")
    return output


def p2wpkh_address(pubkey_hash: bytes, hrp: str = "bc") -> str:
    values = [0] + _convertbits(pubkey_hash, 8, 5)
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + values + [0] * 6) ^ 1
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[value] for value in values + checksum)


def address_from_hash160(pubkey_hash: bytes, address_type: str = "p2pkh") -> str:
    if address_type == "p2wpkh":
        return p2wpkh_address(pubkey_hash)
    if address_type != "p2pkh":
        raise ValueError(f"unsupported address type: {address_type}")
    return base58check(b"\x00", pubkey_hash)


@dataclass(frozen=True)
class KeyMaterial:
    private_scalar: int
    private_key_hex: str
    public_key_hex: str
    sha256_hex: str
    ripemd160_hex: str
    hash160_hex: str
    p2pkh_address: str
    p2wpkh_address: str


def coincurve_material(scalar: int) -> KeyMaterial:
    if not 1 <= scalar < SECP256K1_ORDER:
        raise ValueError("private scalar is outside the secp256k1 range")
    private = PrivateKey.from_int(scalar)
    public = private.public_key.format(compressed=True)
    digest_sha = sha256(public)
    digest_ripemd = ripemd160(digest_sha)
    digest_hash160 = ripemd160(digest_sha)
    return KeyMaterial(
        private_scalar=scalar,
        private_key_hex=private.secret.hex(),
        public_key_hex=public.hex(),
        sha256_hex=digest_sha.hex(),
        ripemd160_hex=digest_ripemd.hex(),
        hash160_hex=digest_hash160.hex(),
        p2pkh_address=address_from_hash160(digest_hash160, "p2pkh"),
        p2wpkh_address=address_from_hash160(digest_hash160, "p2wpkh"),
    )


def bitcoinlib_material(scalar: int) -> KeyMaterial:
    # bitcoinlib creates a local database directory at import time. Keep it
    # in /tmp and never use its wallet/network APIs for Key Lab operations.
    os.environ.setdefault("BCL_DATA_DIR", "/tmp/chain-trace-bitcoinlib")
    from bitcoinlib.keys import Key

    key = Key(import_key=scalar, is_private=True, network="bitcoin")
    public = bytes(key.public_byte)
    digest_sha = sha256(public)
    digest_ripemd = ripemd160(digest_sha)
    digest_hash160 = ripemd160(digest_sha)
    return KeyMaterial(
        private_scalar=scalar,
        private_key_hex=f"{scalar:064x}",
        public_key_hex=public.hex(),
        sha256_hex=digest_sha.hex(),
        ripemd160_hex=digest_ripemd.hex(),
        hash160_hex=digest_hash160.hex(),
        p2pkh_address=address_from_hash160(digest_hash160, "p2pkh"),
        p2wpkh_address=address_from_hash160(digest_hash160, "p2wpkh"),
    )


ENGINES: Dict[str, Callable[[int], KeyMaterial]] = {
    "coincurve": coincurve_material,
    "bitcoinlib": bitcoinlib_material,
}


def verify_material(material: KeyMaterial) -> bool:
    return (
        len(material.private_key_hex) == 64
        and len(material.public_key_hex) == 66
        and material.hash160_hex == hash160(bytes.fromhex(material.public_key_hex)).hex()
        and material.p2pkh_address == address_from_hash160(bytes.fromhex(material.hash160_hex), "p2pkh")
        and material.p2wpkh_address == address_from_hash160(bytes.fromhex(material.hash160_hex), "p2wpkh")
    )


def correctness_oracle(scalars=(1, 2, 0x12345, 0xDEADBEEF)) -> Dict[str, Dict[str, str]]:
    matrix = {stage: {} for stage in ("private_scalar", "pubkey", "sha256", "ripemd160", "hash160", "address")}
    reference = [ENGINES["coincurve"](scalar) for scalar in scalars]
    for engine_name in ("bitcoinlib", "coincurve"):
        try:
            candidate = [ENGINES[engine_name](scalar) for scalar in scalars]
            checks = [
                all(a.private_scalar == b.private_scalar for a, b in zip(reference, candidate)),
                all(a.public_key_hex == b.public_key_hex for a, b in zip(reference, candidate)),
                all(a.sha256_hex == b.sha256_hex for a, b in zip(reference, candidate)),
                all(a.ripemd160_hex == b.ripemd160_hex for a, b in zip(reference, candidate)),
                all(a.hash160_hex == b.hash160_hex for a, b in zip(reference, candidate)),
                all(a.p2pkh_address == b.p2pkh_address and a.p2wpkh_address == b.p2wpkh_address for a, b in zip(reference, candidate)),
            ]
            for stage, passed in zip(matrix, checks):
                matrix[stage][engine_name] = "PASS" if passed else "FAIL"
        except Exception as exc:
            for stage in matrix:
                matrix[stage][engine_name] = f"UNAVAILABLE: {type(exc).__name__}"
    if any(value != "PASS" for stage in matrix.values() for value in stage.values()):
        raise RuntimeError("keylab correctness oracle failed; benchmark aborted")
    return matrix
