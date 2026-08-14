"""Registry for format-specific artifact adapters."""

from .ethereum_keystore import EthereumV3KeystoreAdapter
from .electrum import ElectrumArtifactAdapter
from .bitcoin_core import BitcoinCoreArtifactAdapter

ADAPTERS = [EthereumV3KeystoreAdapter(), ElectrumArtifactAdapter(), BitcoinCoreArtifactAdapter()]


def adapter_for(artifact) -> object | None:
    for adapter in ADAPTERS:
        if adapter.inspect(artifact).detected:
            return adapter
    return None


def inspect_artifact(artifact):
    adapter = adapter_for(artifact)
    if adapter is None:
        return {"adapter_id": None, "detected": False, "encrypted": False, "warnings": ["No implemented format-specific adapter matched"]}
    inspection = adapter.inspect(artifact)
    return {"adapter_id": inspection.adapter_id, "detected": inspection.detected, "encrypted": inspection.encrypted, "kdf": inspection.kdf, "cipher": inspection.cipher, "estimated_work": inspection.estimated_work, "public_metadata": inspection.public_metadata, "warnings": inspection.warnings}
