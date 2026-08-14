"""Opt-in public-only history verification.

Providers receive only a network and derived public address. The core recovery
engine does not know whether the implementation uses Esplora, Electrum,
Blockscout, or an RPC endpoint.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Iterable, Protocol
from urllib.request import Request, urlopen


class PublicHistoryProvider(Protocol):
    def address_used(self, network: str, address: str) -> bool: ...
    def transactions(self, network: str, address: str, limit: int = 20) -> list: ...
    def first_seen(self, network: str, address: str): ...


@dataclass
class PublicHistoryEvidence:
    used: bool | None
    tx_count: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    native_balance: int | None = None
    evidence_strength: str = "UNKNOWN"
    source: str = "unknown"


def _get_json(url, *, timeout=8):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "Chain-Trace-owner-recovery/1"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class EsploraProvider:
    def __init__(self, base_url: str): self.base_url = base_url.rstrip("/")
    def evidence(self, network: str, address: str) -> PublicHistoryEvidence:
        txs = _get_json(f"{self.base_url}/address/{address}/txs")
        confirmed = [tx for tx in txs if tx.get("status", {}).get("confirmed")]
        timestamps = [tx["status"].get("block_time") for tx in confirmed if tx["status"].get("block_time")]
        balance = sum(int(item.get("value", 0)) for item in _get_json(f"{self.base_url}/address/{address}/utxo"))
        return PublicHistoryEvidence(bool(txs), len(txs), datetime.fromtimestamp(min(timestamps), timezone.utc) if timestamps else None, datetime.fromtimestamp(max(timestamps), timezone.utc) if timestamps else None, balance, "STRONG" if txs else "OBSERVED_EMPTY", "esplora")
    def address_used(self, network, address): return bool(self.evidence(network, address).used)
    def transactions(self, network, address, limit=20): return _get_json(f"{self.base_url}/address/{address}/txs")[:limit]
    def first_seen(self, network, address): return self.evidence(network, address).first_seen


class EvmJsonRpcProvider:
    def __init__(self, rpc_url: str): self.rpc_url = rpc_url
    def _call(self, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        request = Request(self.rpc_url, data=body, headers={"Content-Type": "application/json", "User-Agent": "Chain-Trace-owner-recovery/1"})
        with urlopen(request, timeout=8) as response:
            return json.loads(response.read().decode()).get("result")
    def evidence(self, network, address):
        balance = int(self._call("eth_getBalance", [address, "latest"]), 16)
        nonce = int(self._call("eth_getTransactionCount", [address, "latest"]), 16)
        return PublicHistoryEvidence(nonce > 0 or balance > 0, None, None, None, balance, "STRONG" if nonce > 0 else "BALANCE_ONLY", "evm-json-rpc")
    def address_used(self, network, address): return bool(self.evidence(network, address).used)
    def transactions(self, network, address, limit=20): return []
    def first_seen(self, network, address): return None


class BlockscoutProvider:
    def __init__(self, base_url: str): self.base_url = base_url.rstrip("/")
    def evidence(self, network, address):
        payload = _get_json(f"{self.base_url}/api?module=account&action=txlist&address={address}&page=1&offset=100")
        txs = payload.get("result", []) if isinstance(payload, dict) else []
        stamps = [int(tx["timeStamp"]) for tx in txs if str(tx.get("timeStamp", "")).isdigit()]
        return PublicHistoryEvidence(bool(txs), len(txs), datetime.fromtimestamp(min(stamps), timezone.utc) if stamps else None, datetime.fromtimestamp(max(stamps), timezone.utc) if stamps else None, None, "STRONG" if txs else "OBSERVED_EMPTY", "blockscout")
    def address_used(self, network, address): return bool(self.evidence(network, address).used)
    def transactions(self, network, address, limit=20): return self.evidence(network, address).tx_count or 0
    def first_seen(self, network, address): return self.evidence(network, address).first_seen


class SolanaJsonRpcProvider:
    def __init__(self, rpc_url: str): self.rpc_url = rpc_url
    def _call(self, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        request = Request(self.rpc_url, data=body, headers={"Content-Type": "application/json", "User-Agent": "Chain-Trace-owner-recovery/1"})
        with urlopen(request, timeout=8) as response: return json.loads(response.read().decode()).get("result")
    def evidence(self, network, address):
        signatures = self._call("getSignaturesForAddress", [address, {"limit": 100}]) or []
        balance = self._call("getBalance", [address]).get("value")
        return PublicHistoryEvidence(bool(signatures), len(signatures), None, None, balance, "STRONG" if signatures else "BALANCE_ONLY", "solana-json-rpc")
    def address_used(self, network, address): return bool(self.evidence(network, address).used)
    def transactions(self, network, address, limit=20): return self._call("getSignaturesForAddress", [address, {"limit": limit}]) or []
    def first_seen(self, network, address): return None


class InMemoryPublicHistoryProvider:
    """Small test/local adapter; production adapters can implement the protocol."""
    def __init__(self, history=None):
        self.history = history or {}

    def address_used(self, network: str, address: str) -> bool:
        item = self.history.get((network, address), self.history.get(address, {}))
        return bool(item.get("used", bool(item.get("transactions")))) if isinstance(item, dict) else bool(item)

    def transactions(self, network: str, address: str, limit: int = 20) -> list:
        item = self.history.get((network, address), self.history.get(address, {}))
        return list(item.get("transactions", []))[:limit] if isinstance(item, dict) else []

    def first_seen(self, network: str, address: str):
        item = self.history.get((network, address), self.history.get(address, {}))
        return item.get("first_seen") if isinstance(item, dict) else None


def verify_public_history(addresses: Iterable[str], *, network="unknown", enabled=False, provider: PublicHistoryProvider | None = None, max_queries=0):
    addresses = list(addresses)[:max(0, max_queries) if max_queries else len(addresses)]
    if not enabled:
        return {"enabled": False, "offline": True, "checked": 0, "history": {}}
    if provider is None:
        return {"enabled": False, "offline": True, "checked": 0, "history": {}, "reason": "No read-only provider configured"}
    history = {}
    for address in addresses:
        try:
            evidence = provider.evidence(network, address) if hasattr(provider, "evidence") else None
            history[address] = {"used": bool(evidence.used if evidence else provider.address_used(network, address)), "transactions": evidence.tx_count if evidence else provider.transactions(network, address), "first_seen": evidence.first_seen.isoformat() if evidence and evidence.first_seen else (provider.first_seen(network, address).isoformat() if hasattr(provider.first_seen(network, address), "isoformat") else provider.first_seen(network, address)), "last_seen": evidence.last_seen.isoformat() if evidence and evidence.last_seen else None, "native_balance": evidence.native_balance if evidence else None, "evidence_strength": evidence.evidence_strength if evidence else "UNKNOWN", "source": evidence.source if evidence else "custom"}
        except Exception:
            history[address] = {"status": "unavailable"}
    return {"enabled": True, "offline": False, "checked": len(addresses), "history": history}
