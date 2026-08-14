"""Local artifact metadata detection without automatic secret decryption."""

import json
from pathlib import Path


def detect_artifact(path: str | None):
    if not path:
        return {"artifact_type": None, "detected": False, "metadata": {}, "secret_decryption_attempted": False, "recommendation": "Supply an owner-held artifact path when available."}
    target = Path(path)
    suffix = target.suffix.lower()
    artifact_type = {".json": "json-or-keystore", ".dat": "bitcoin-core-or-binary-wallet", ".wallet": "electrum-or-wallet-file", ".txt": "watch-only-or-export"}.get(suffix, "unknown")
    metadata = {"filename": target.name, "suffix": suffix, "exists": target.exists()}
    if target.exists() and suffix == ".json" and target.stat().st_size <= 2_000_000:
        try:
            value = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                keys = {str(key).lower() for key in value.keys()}
                if "crypto" in keys or "cipher" in keys or "kdf" in keys:
                    artifact_type = "ethereum-json-keystore"
                elif "vault" in keys or ("data" in keys and "salt" in keys):
                    artifact_type = "metamask-or-browser-vault"
                elif "accounts" in keys or "derivationpath" in keys:
                    artifact_type = "watch-only-or-account-export"
                metadata["top_level_keys"] = [key for key in value.keys() if key.lower() not in {"crypto", "ciphertext", "privatekey", "private_key", "mnemonic", "seed", "vault", "data"}][:30]
                if "address" in value:
                    metadata["has_public_address"] = True
        except (OSError, ValueError, UnicodeDecodeError):
            metadata["parse_status"] = "unparsed"
    return {"artifact_type": artifact_type, "detected": target.exists(), "metadata": metadata, "supports_local_password": artifact_type in {"ethereum-json-keystore", "metamask-or-browser-vault", "electrum-or-wallet-file", "bitcoin-core-or-binary-wallet"}, "secret_decryption_attempted": False, "recommendation": "Inspect public metadata first; decrypt secret-bearing material only after explicit owner authorization and local password entry."}
