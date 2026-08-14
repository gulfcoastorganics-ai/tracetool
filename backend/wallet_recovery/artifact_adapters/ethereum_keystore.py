"""Ethereum Web3 Secret Storage (V3) adapter.

Password verification performs KDF, MAC validation, and AES-CTR decryption in
memory. The decrypted private key is used only to calculate a public address
and is immediately released; it is never returned or persisted.
"""

import json
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Hash import SHA1, SHA256

from .base import ArtifactInspection, ArtifactPasswordResult


def _load(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        return json.loads(value.decode("utf-8"))
    if isinstance(value, str):
        text = value
        if text.lstrip().startswith("{"):
            return json.loads(text)
        return json.loads(Path(value).read_text(encoding="utf-8"))
    raise ValueError("Unsupported keystore input")


class EthereumV3KeystoreAdapter:
    adapter_id = "ethereum-v3-keystore"

    def _parts(self, artifact):
        value = _load(artifact)
        crypto = value.get("crypto") or value.get("Crypto")
        if not isinstance(crypto, dict):
            raise ValueError("Ethereum V3 crypto section not found")
        return value, crypto, crypto.get("kdf"), crypto.get("kdfparams") or {}, crypto.get("cipher"), crypto.get("cipherparams") or {}, bytes.fromhex(crypto.get("ciphertext", ""))

    def inspect(self, artifact):
        try:
            value, crypto, kdf, params, cipher, cipherparams, ciphertext = self._parts(artifact)
            if cipher != "aes-128-ctr":
                return ArtifactInspection(self.adapter_id, True, True, kdf, cipher, warnings=["Unsupported cipher; password verification not attempted"])
            work = self.estimate_work(artifact)
            metadata = {"version": value.get("version"), "id_present": bool(value.get("id")), "address_present": bool(value.get("address")), "address": value.get("address") if value.get("address") else None, "dklen": params.get("dklen"), "iv_bytes": len(bytes.fromhex(cipherparams.get("iv", ""))), "ciphertext_bytes": len(ciphertext)}
            return ArtifactInspection(self.adapter_id, True, True, kdf, cipher, work, metadata)
        except Exception as exc:
            return ArtifactInspection(self.adapter_id, False, False, warnings=["Not a valid Ethereum V3 keystore"])

    def estimate_work(self, artifact):
        _, _, kdf, params, _, _, _ = self._parts(artifact)
        if kdf == "scrypt":
            return {"kdf": "scrypt", "n": int(params.get("n", 0)), "r": int(params.get("r", 0)), "p": int(params.get("p", 0)), "dklen": int(params.get("dklen", 0))}
        if kdf == "pbkdf2":
            return {"kdf": "pbkdf2", "iterations": int(params.get("c", 0)), "prf": params.get("prf"), "dklen": int(params.get("dklen", 0))}
        return {"kdf": kdf, "supported": False}

    def _derive(self, password: str, kdf: str, params: dict):
        salt = bytes.fromhex(params["salt"])
        dklen = int(params["dklen"])
        if kdf == "scrypt":
            return scrypt(password.encode("utf-8"), salt, dklen, N=int(params["n"]), r=int(params["r"]), p=int(params["p"]))
        if kdf == "pbkdf2":
            prf = params.get("prf", "hmac-sha256").lower()
            hmac_hash = SHA1 if prf.endswith("sha1") else SHA256
            return PBKDF2(password.encode("utf-8"), salt, dklen, count=int(params["c"]), hmac_hash_module=hmac_hash)
        raise ValueError("Unsupported Ethereum V3 KDF")

    def verify_password_candidate(self, artifact, password):
        try:
            value, crypto, kdf, params, cipher, cipherparams, ciphertext = self._parts(artifact)
            if value.get("version") != 3 or cipher != "aes-128-ctr":
                return ArtifactPasswordResult(False, error="Unsupported Ethereum V3 cipher or version")
            derived = self._derive(password, kdf, params)
            mac = keccak.new(digest_bits=256, data=derived[16:32] + ciphertext).hexdigest()
            expected = str(crypto.get("mac", "")).lower()
            if mac.lower() != expected:
                return ArtifactPasswordResult(False, estimated_work=self.estimate_work(artifact), error="Password or keystore authentication failed")
            iv = bytes.fromhex(cipherparams["iv"])
            plaintext = AES.new(derived[:16], AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big")).decrypt(ciphertext)
            if len(plaintext) != 32:
                return ArtifactPasswordResult(False, error="Authenticated payload has unexpected length")
            public = self._public_evidence(plaintext, value)
            del plaintext, derived
            return ArtifactPasswordResult(True, public_evidence=public, estimated_work=self.estimate_work(artifact))
        except Exception:
            return ArtifactPasswordResult(False, error="Password verification failed for this keystore")

    def _public_evidence(self, private_key: bytes, value: dict):
        from coincurve import PrivateKey
        public_key = PrivateKey(private_key).public_key.format(compressed=False)[1:]
        digest = keccak.new(digest_bits=256, data=public_key).hexdigest()
        return {"network": "ethereum", "address": "0x" + digest[-40:], "artifact_address": value.get("address"), "proof": "CRYPTOGRAPHIC_ARTIFACT_MATCH"}

    def extract_public_evidence(self, artifact, password):
        return self.verify_password_candidate(artifact, password).public_evidence

    def recover(self, artifact, password):
        return self.verify_password_candidate(artifact, password)
