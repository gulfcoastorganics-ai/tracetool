import hashlib
import struct
import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache

try:
    import bitcoin
    from bitcoin.wallet import CKey
    from bitcoin.core import b2lx, lx, COutPoint, CTxIn, CTxOut, CTransaction
    from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
    HAS_BITCOIN_CORE = True
except ImportError:
    HAS_BITCOIN_CORE = False

try:
    import bdb
    HAS_BDB = True
except ImportError:
    HAS_BDB = False

from backend.config.settings import BITCOIN_CONFIG


@dataclass
class TxOutput:
    txid: str
    vout: int
    value: float
    script_sig: str
    address: str
    is_change: bool = False
    cluster_id: Optional[int] = None


@dataclass
class BitcoinTransaction:
    txid: str
    inputs: List[Dict]
    outputs: List[TxOutput]
    timestamp: int
    version: int
    locktime: int
    size: int = 0
    fee: Optional[float] = None


@dataclass
class AddressCluster:
    addresses: Set[str]
    heuristic: str
    confidence: float
    transactions_used: List[str]


class UTXOParser:
    def __init__(self, block_data_path: str = None):
        self.blockchain_path = block_data_path or BITCOIN_CONFIG.get('blockchain_path', '')
        self._cache = {}
        self.transactions = {}
        self.utxos = {}
        self.address_txs = {}
    
    def parse_tx_dat(self, tx_data: bytes) -> BitcoinTransaction:
        try:
            import io
            stream = io.BytesIO(tx_data)
            
            version = struct.unpack('<I', stream.read(4))[0]
            
            marker = stream.read(1)
            if marker == b'\x00':
                flag = stream.read(1)
                input_count = self._read_varint(stream)
            else:
                input_count = self._read_varint(marker)
            
            inputs = []
            for _ in range(input_count):
                txid_bytes = stream.read(32)[::-1]
                vout = struct.unpack('<I', stream.read(4))[0]
                script_len = self._read_varint(stream)
                script_sig = stream.read(script_len).hex()
                sequence = struct.unpack('<I', stream.read(4))[0]
                
                inputs.append({
                    'txid': txid_bytes.hex(),
                    'vout': vout,
                    'script_sig': script_sig,
                    'sequence': sequence
                })
            
            output_count = self._read_varint(stream)
            outputs = []
            for _ in range(output_count):
                value = struct.unpack('<Q', stream.read(8))[0] / 100000000
                script_len = self._read_varint(stream)
                script_sig = stream.read(script_len)
                
                address = self._extract_address(script_sig)
                outputs.append(TxOutput(
                    txid='',
                    vout=0,
                    value=value,
                    script_sig=script_sig.hex(),
                    address=address or '',
                    is_change=False
                ))
            
            locktime = struct.unpack('<I', stream.read(4))[0]
            
            return BitcoinTransaction(
                txid='',
                inputs=inputs,
                outputs=outputs,
                timestamp=0,
                version=version,
                locktime=locktime
            )
        except Exception as e:
            raise ValueError(f"Failed to parse transaction: {e}")
    
    def _read_varint(self, stream) -> int:
        first_byte = stream.read(1)
        if not first_byte:
            return 0
        
        n = first_byte[0]
        if n < 0xfd:
            return n
        elif n == 0xfd:
            return struct.unpack('<H', stream.read(2))[0]
        else:
            return struct.unpack('<I', stream.read(4))[0]
    
    def _extract_address(self, script: bytes) -> Optional[str]:
        if len(script) < 25:
            return None
        
        if script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14:
            pubkey_hash = script[3:23].hex()
            return self._p2pkh_to_address(pubkey_hash)
        
        if script[0] == 0x32:
            return self._p2sh_to_address(script)
        
        if script[0:2] == b'\x00\x14':
            return self._bech32_to_address(script[2:])
        
        return None
    
    def _p2pkh_to_address(self, pubkey_hash: str) -> str:
        import base58
        version = bytes([0x00])
        payload = version + bytes.fromhex(pubkey_hash)
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()
    
    def _p2sh_to_address(self, script: bytes) -> str:
        import base58
        if len(script) < 22:
            return ''
        hash160 = script[-20:].hex()
        version = bytes([0x05])
        payload = version + bytes.fromhex(hash160)
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()
    
    def _bech32_to_address(self, pubkey_hash: bytes) -> str:
        return f"bc1q{pubkey_hash.hex()[:39]}"
    
    def load_transactions_from_dat(self, dat_path: str) -> Dict[str, BitcoinTransaction]:
        if not self.blockchain_path:
            return {}
        
        transactions = {}
        current_block_height = 0
        
        try:
            with open(dat_path, 'rb') as f:
                buffer = f.read()
                
            pos = 0
            while pos < len(buffer):
                magic = buffer[pos:pos+4]
                if magic != b'\xf9beb4c9':
                    pos += 1
                    continue
                
                pos += 4
                block_size = struct.unpack('<I', buffer[pos:pos+4])[0]
                pos += 4
                block_timestamp = struct.unpack('<I', buffer[pos:pos+4])[0]
                pos += 4 + 12
                
                block_data = buffer[pos:pos+block_size]
                pos += block_size
                
                try:
                    txs = self._parse_block_transactions(block_data)
                    for tx in txs:
                        tx.txid = hashlib.sha256(hashlib.sha256(block_data).digest()).hexdigest()
                        transactions[tx.txid] = tx
                except Exception:
                    pass
                
                current_block_height += 1
        except Exception:
            pass
        
        self.transactions = transactions
        return transactions
    
    def _parse_block_transactions(self, block_data: bytes) -> List[BitcoinTransaction]:
        import io
        stream = io.BytesIO(block_data)
        
        tx_count = self._read_varint(stream)
        transactions = []
        
        for _ in range(tx_count):
            start_pos = stream.tell()
            try:
                tx = self.parse_tx_dat(block_data[start_pos:])
                transactions.append(tx)
            except Exception:
                continue
        
        return transactions


class BitcoinHeuristics:
    def __init__(self):
        self.clusters = {}
        self.cioh_map = {}
        self.change_addresses = set()
    
    def detect_coinjoins(
        self, 
        transactions: List[BitcoinTransaction],
        min_outputs: int = 3,
        value_threshold: float = 0.0
    ) -> List[Dict]:
        coinjoins = []
        
        for tx in transactions:
            if len(tx.outputs) < min_outputs:
                continue
            
            values = [o.value for o in tx.outputs if o.value > value_threshold]
            
            if not values:
                continue
            
            value_groups = {}
            for v in values:
                if v not in value_groups:
                    value_groups[v] = []
                value_groups[v].append(v)
            
            equal_value_groups = {
                v: txs for v, txs in value_groups.items() 
                if len(txs) >= 2
            }
            
            if len(equal_value_groups) >= 2:
                cluster = self._create_coinjoin_cluster(tx, equal_value_groups)
                coinjoins.append(cluster)
        
        return coinjoins
    
    def _create_coinjoin_cluster(self, tx: BitcoinTransaction, value_groups: dict) -> Dict:
        all_addresses = set()
        equal_outputs = []
        
        for output in tx.outputs:
            for value, outputs in value_groups.items():
                if output.value == value:
                    equal_outputs.append(output)
                    all_addresses.add(output.address)
        
        return {
            'type': 'coinjoin',
            'txid': tx.txid,
            'timestamp': tx.timestamp,
            'input_count': len(tx.inputs),
            'output_count': len(tx.outputs),
            'equal_outputs': len(equal_outputs),
            'addresses': list(all_addresses),
            'total_value': sum(o.value for o in tx.outputs),
            'confidence': min(0.95, len(equal_outputs) / max(len(tx.outputs), 1))
        }
    
    def apply_cioh(
        self, 
        transactions: List[BitcoinTransaction]
    ) -> Dict[str, Set[str]]:
        address_clusters = {}
        
        for tx in transactions:
            if len(tx.inputs) <= 1:
                continue
            
            input_addresses = set()
            for inp in tx.inputs:
                addr = self._get_input_address(inp, transactions)
                if addr:
                    input_addresses.add(addr)
            
            if not input_addresses:
                continue
            
            cluster_id = hash(frozenset(input_addresses)) % 1000000
            
            for output in tx.outputs:
                if output.address not in address_clusters:
                    address_clusters[output.address] = set()
                address_clusters[output.address].add(cluster_id)
            
            for addr in input_addresses:
                if addr not in address_clusters:
                    address_clusters[addr] = set()
                address_clusters[addr].add(cluster_id)
        
        self.cioh_map = address_clusters
        return address_clusters
    
    def _get_input_address(self, inp: Dict, transactions: List[BitcoinTransaction]) -> Optional[str]:
        for tx in transactions:
            if tx.txid == inp['txid']:
                if inp['vout'] < len(tx.outputs):
                    return tx.outputs[inp['vout']].address
        
        return None
    
    def detect_change_addresses(
        self, 
        transactions: List[BitcoinTransaction]
    ) -> Set[str]:
        change_addresses = set()
        
        for tx in transactions:
            if len(tx.outputs) != 2:
                continue
            
            outputs = sorted(tx.outputs, key=lambda o: o.value, reverse=True)
            
            if len(outputs) < 2:
                continue
            
            large_output = outputs[0]
            small_output = outputs[1]
            
            if small_output.address.startswith('bc1') or small_output.address.startswith('1') or small_output.address.startswith('3'):
                ratio = small_output.value / large_output.value if large_output.value > 0 else 0
                
                if ratio < 0.1 or small_output.value < 0.0001:
                    change_addresses.add(small_output.address)
                
                addresses_in_tx = {o.address for o in tx.outputs}
                input_addrs = set()
                for inp in tx.inputs:
                    addr = self._get_input_address(inp, transactions)
                    if addr:
                        input_addrs.add(addr)
                
                for addr in input_addrs:
                    if addr not in addresses_in_tx:
                        continue
                
                if large_output.address in input_addrs and small_output.address not in input_addrs:
                    change_addresses.add(small_output.address)
        
        self.change_addresses = change_addresses
        return change_addresses
    
    def detect_peeling_chains(
        self, 
        transactions: List[BitcoinTransaction],
        change_addresses: Set[str]
    ) -> List[Dict]:
        peeling_chains = []
        
        address_txs = {}
        for tx in transactions:
            for inp in tx.inputs:
                addr = self._get_input_address(inp, transactions)
                if addr:
                    if addr not in address_txs:
                        address_txs[addr] = []
                    address_txs[addr].append(tx)
        
        for address, txs in address_txs.items():
            if address not in change_addresses:
                continue
            
            chain = []
            current_addr = address
            
            while current_addr in address_txs:
                tx = address_txs[current_addr][0]
                chain.append({
                    'txid': tx.txid,
                    'address': current_addr,
                    'output_count': len(tx.outputs)
                })
                
                next_addr = None
                for out in tx.outputs:
                    if out.address != current_addr and out.address in address_txs:
                        next_addr = out.address
                        break
                
                if next_addr and next_addr not in [c.get('address') for c in chain]:
                    current_addr = next_addr
                else:
                    break
            
            if len(chain) > 1:
                peeling_chains.append({
                    'type': 'peeling_chain',
                    'length': len(chain),
                    'chain': chain,
                    'starting_address': address
                })
        
        return peeling_chains


class BitcoinForensicsReport:
    def __init__(self):
        self.cioh_results = {}
        self.coinjoins = []
        self.change_addresses = set()
        self.peeling_chains = []
        self.analysis_timestamp = None
    
    def generate(
        self,
        transactions: List[BitcoinTransaction]
    ) -> Dict:
        heuristics = BitcoinHeuristics()
        
        self.cioh_results = heuristics.apply_cioh(transactions)
        self.coinjoins = heuristics.detect_coinjoins(transactions)
        self.change_addresses = heuristics.detect_change_addresses(transactions)
        self.peeling_chains = heuristics.detect_peeling_chains(transactions, self.change_addresses)
        
        self.analysis_timestamp = datetime.utcnow().isoformat()
        
        return self.to_dict()
    
    def to_dict(self) -> Dict:
        return {
            'analysis_timestamp': self.analysis_timestamp,
            'common_input_ownership': {
                str(k): list(v) for k, v in self.cioh_results.items()
            },
            'coinjoins_detected': self.coinjoins,
            'change_addresses': list(self.change_addresses),
            'peeling_chains': self.peeling_chains
        }
    
    def to_markdown(self) -> str:
        lines = [
            "# Bitcoin Forensic Analysis Report",
            f"\n**Generated:** {self.analysis_timestamp}",
            "",
            "## Summary",
            f"- Addresses with CIOH applied: {len(self.cioh_results)}",
            f"- CoinJoin transactions detected: {len(self.coinjoins)}",
            f"- Change addresses identified: {len(self.change_addresses)}",
            f"- Peeling chains detected: {len(self.peeling_chains)}",
            ""
        ]
        
        if self.coinjoins:
            lines.append("## CoinJoin Detections")
            for cj in self.coinjoins:
                lines.append(f"\n### Transaction {cj['txid'][:16]}...")
                lines.append(f"- Inputs: {cj['input_count']}")
                lines.append(f"- Equal Outputs: {cj['equal_outputs']}")
                lines.append(f"- Total Value: {cj['total_value']} BTC")
                lines.append(f"- Confidence: {cj['confidence']:.2%}")
        
        if self.change_addresses:
            lines.append("\n## Change Addresses")
            lines.append(f"```\n{chr(10).join(self.change_addresses)}\n```")
        
        if self.peeling_chains:
            lines.append("\n## Peeling Chains")
            for chain in self.peeling_chains:
                lines.append(f"\n- Chain length: {chain['length']}")
                lines.append(f"  Starting: {chain['starting_address'][:16]}...")
        
        return '\n'.join(lines)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
    
    def save_report(self, output_dir: str) -> Tuple[str, str]:
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        json_path = f"{output_dir}/report.json"
        md_path = f"{output_dir}/report.md"
        
        with open(json_path, 'w') as f:
            f.write(self.to_json())
        
        with open(md_path, 'w') as f:
            f.write(self.to_markdown())
        
        return json_path, md_path
