"""Electrum wallet-file inspection and native BIE1/BIE2 decryption.

Electrum storage encryption is not a generic JSON password check. The file is
base64 encoded ECIES data with a BIE1/BIE2 magic, a password-derived secp256k1
key, AES-128-CBC and an HMAC-SHA256 authentication tag. Plaintext is parsed
only in memory and reduced to public evidence before the decrypted buffer is
released.
"""

import base64
import hashlib
import hmac
import json
import zlib
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from coincurve import PrivateKey, PublicKey
from coincurve.utils import GROUP_ORDER_INT

from .base import ArtifactInspection, ArtifactPasswordResult


def _load(value):
    if isinstance(value, dict): return value
    if isinstance(value, bytes): return json.loads(value.decode())
    if isinstance(value, str):
        if value.lstrip().startswith("{"): return json.loads(value)
        path = Path(value)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        # Raw encrypted storage is base64 text, not JSON.
        return value.strip()
    raise ValueError("Unsupported Electrum artifact input")


def _storage_bytes(value):
    if isinstance(value, bytes):
        raw = value.strip()
    elif isinstance(value, str):
        path = Path(value)
        raw = path.read_bytes().strip() if path.exists() else value.encode("ascii")
    else:
        return None
    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception:
        return None
    return decoded if decoded[:4] in {b"BIE1", b"BIE2"} else None


def _private_key_from_password(password):
    if password is None:
        password = ""
    if not isinstance(password, str):
        raise ValueError("Electrum password must be text")
    secret = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), b"", 1024)
    scalar = int.from_bytes(secret, "big") % GROUP_ORDER_INT
    if scalar == 0:
        raise ValueError("Electrum password produced an invalid scalar")
    return PrivateKey(scalar.to_bytes(32, "big"))


def _ecies_decrypt(encoded, password, expected_magic):
    """Decrypt Electrum's BIE1/BIE2 ECIES envelope."""
    raw = _storage_bytes(encoded)
    if raw is None or len(raw) < 85:
        raise ValueError("Invalid Electrum encrypted storage")
    if raw[:4] != expected_magic:
        raise ValueError("Electrum storage encryption version mismatch")
    ephemeral = PublicKey(raw[4:37])
    ciphertext = raw[37:-32]
    received_mac = raw[-32:]
    private = _private_key_from_password(password)
    shared = ephemeral.multiply(private.secret)
    key = hashlib.sha512(shared.format(compressed=True)).digest()
    iv, encryption_key, mac_key = key[:16], key[16:32], key[32:]
    expected_mac = hmac.new(mac_key, raw[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("Electrum password authentication failed")
    decrypted = AES.new(encryption_key, AES.MODE_CBC, iv).decrypt(ciphertext)
    return unpad(decrypted, AES.block_size)


def _decrypt_storage(value, password):
    raw = _storage_bytes(value)
    if raw is None:
        raise ValueError("Not native Electrum encrypted storage")
    magic = raw[:4]
    plaintext = _ecies_decrypt(value, password, magic)
    try:
        decompressed = zlib.decompress(plaintext)
        return json.loads(decompressed.decode("utf-8"))
    finally:
        # The immutable intermediate is released immediately after parsing.
        del plaintext


class ElectrumArtifactAdapter:
    adapter_id = "electrum-wallet"

    def _value(self, artifact):
        return _load(artifact)

    def inspect(self, artifact):
        raw = _storage_bytes(artifact) if not isinstance(artifact, dict) else None
        if raw is not None:
            version = raw[:4].decode("ascii")
            return ArtifactInspection(self.adapter_id, True, True, "pbkdf2-hmac-sha512", "ECIES-AES-128-CBC", {"iterations": 1024, "magic": version, "authenticated": True}, {"storage_encryption": version, "wallet_metadata_available": False}, [])
        try:
            value = self._value(artifact)
        except Exception:
            return ArtifactInspection(self.adapter_id, False, False, warnings=["Not an Electrum JSON wallet"])
        if not any(key in value for key in ("wallet_type", "keystore", "seed_version", "use_encryption", "x1", "x2")):
            return ArtifactInspection(self.adapter_id, False, False)
        encrypted = bool(value.get("use_encryption") or value.get("storage_encryption") or any(isinstance(item, str) and item.startswith("BIE") for item in value.values()))
        keystores = [item for key, item in value.items() if key == "keystore" or key.startswith("x") and isinstance(item, dict)]
        public = self.extract_public_evidence(value)
        return ArtifactInspection(self.adapter_id, True, encrypted, "electrum-password-or-hardware" if encrypted else None, "ECIES-AES-CBC" if encrypted else None, {"pbkdf2": 1024 if encrypted else 0}, {"wallet_type": value.get("wallet_type"), "storage_version": value.get("seed_version"), "seed_version": value.get("seed_version"), "use_change": value.get("use_change"), "gap_limit": value.get("gap_limit"), "keystore_count": len(keystores), **public}, warnings=["Encrypted Electrum storage requires the native Electrum ECIES implementation" ] if encrypted else [])

    def estimate_work(self, artifact):
        inspection = self.inspect(artifact)
        return inspection.estimated_work

    def extract_public_evidence(self, artifact):
        value = self._value(artifact)
        if not isinstance(value, dict):
            return {}
        xpubs = []
        pubkeys = []
        origins = []
        for key, item in value.items():
            if not isinstance(item, dict): continue
            for field in ("xpub", "xpubs", "master_public_key"):
                raw = item.get(field)
                xpubs.extend(raw if isinstance(raw, list) else [raw] if raw else [])
            pubkeys.extend(item.get("pubkeys", []) if isinstance(item.get("pubkeys"), list) else [])
            if item.get("derivation"): origins.append(item["derivation"])
        return {"xpubs": list(dict.fromkeys(xpubs)), "pubkeys": list(dict.fromkeys(pubkeys)), "origins": list(dict.fromkeys(origins)), "addresses": list((value.get("addresses") or {}).keys())[:100] if isinstance(value.get("addresses"), dict) else []}

    def verify_password_candidate(self, artifact, password):
        inspection = self.inspect(artifact)
        if not inspection.detected: return ArtifactPasswordResult(False, error="Not an Electrum wallet")
        if inspection.encrypted:
            try:
                decrypted = _decrypt_storage(artifact, password)
                public = self.extract_public_evidence(decrypted)
                del decrypted
                return ArtifactPasswordResult(True, public_evidence={**public, "proof": "CRYPTOGRAPHIC_ARTIFACT_MATCH", "storage_encryption": inspection.public_metadata.get("storage_encryption")}, estimated_work=inspection.estimated_work)
            except Exception:
                return ArtifactPasswordResult(False, estimated_work=inspection.estimated_work, error="Electrum password authentication failed")
        if password not in (None, ""):
            return ArtifactPasswordResult(False, error="Plaintext Electrum wallet does not accept a password")
        return ArtifactPasswordResult(True, public_evidence=self.extract_public_evidence(artifact), estimated_work=inspection.estimated_work)

    def recover(self, artifact, password):
        return self.verify_password_candidate(artifact, password)

    def extract_public_evidence_with_password(self, artifact, password):
        result = self.verify_password_candidate(artifact, password)
        return result.public_evidence if result.valid else {}
