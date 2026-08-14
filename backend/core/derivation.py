from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from itertools import islice
import hashlib
import struct

try:
    from hdwallet import HDWallet
    from hdwallet.symbols import BTC, ETH, SOL
    HAS_HDWALLET = True
except ImportError:
    HAS_HDWALLET = False

from backend.config.settings import (
    get_derivation_paths,
    get_derivation_chains,
    ChainConfig,
    CHAINS,
    get_chain_config,
    SOLANA_CONFIG,
)

@dataclass
class DerivedAddress:
    path: str
    address: str
    label: str
    chain_type: str
    balance: float = 0.0
    transactions: List[Dict] = None
    
    def __post_init__(self):
        if self.transactions is None:
            self.transactions = []

class DerivationEngine:
    def __init__(self):
        self.has_hdwallet = HAS_HDWALLET
        self.max_addresses = 100
    
    def derive_addresses(
        self, 
        mnemonic: str,
        derivation_type: str = 'ethereum',
        count: int = 10,
        passphrase: str = ''
    ) -> List[DerivedAddress]:
        if not self.has_hdwallet:
            return self._derive_native(mnemonic, derivation_type, count, passphrase)
        
        if derivation_type not in get_derivation_paths():
            raise ValueError(f"Unknown derivation type: {derivation_type}")
        
        path_template = get_derivation_paths()[derivation_type]
        addresses = []
        
        for i in range(count):
            full_path = f"{path_template}/{i}"
            derived = self._derive_with_hdwallet(mnemonic, derivation_type, full_path, passphrase)
            if derived:
                addresses.append(derived)
        
        return addresses
    
    def _derive_with_hdwallet(
        self, 
        mnemonic: str, 
        derivation_type: str, 
        path: str,
        passphrase: str = ''
    ) -> Optional[DerivedAddress]:
        try:
            if derivation_type in ['bip44', 'bip49', 'bip84', 'bitcoin']:
                symbols = BTC
            elif derivation_type == 'ethereum':
                symbols = ETH
            elif derivation_type == 'slip10' or derivation_type == 'solana':
                symbols = SOL
            else:
                return None
            
            try:
                # hdwallet 2.x API.
                hdwallet = HDWallet(
                    mnemonic=mnemonic,
                    passphrase=passphrase,
                    symbol=symbols
                )
                hdwallet.from_path(path)
            except TypeError:
                # hdwallet 3.x renamed the constructor arguments and requires
                # a typed derivation object instead of a path string.
                from hdwallet.cryptocurrencies import Bitcoin, Ethereum, Solana
                from hdwallet.mnemonics import BIP39Mnemonic
                from hdwallet.derivations import (
                    BIP44Derivation,
                    BIP49Derivation,
                    BIP84Derivation,
                )

                cryptocurrency = Ethereum if derivation_type == 'ethereum' else (
                    Solana if derivation_type in ('slip10', 'solana') else Bitcoin
                )
                hdwallet = HDWallet(
                    cryptocurrency=cryptocurrency,
                    passphrase=passphrase,
                )
                hdwallet.from_mnemonic(
                    BIP39Mnemonic(mnemonic)
                )
                derivation_classes = {
                    'bip44': BIP44Derivation,
                    'bitcoin': BIP44Derivation,
                    'bip49': BIP49Derivation,
                    'bip84': BIP84Derivation,
                    'ethereum': BIP44Derivation,
                    'slip10': BIP44Derivation,
                    'solana': BIP44Derivation,
                }
                coin_type = 60 if derivation_type == 'ethereum' else (
                    501 if derivation_type in ('slip10', 'solana') else 0
                )
                hdwallet.from_derivation(
                    derivation_classes[derivation_type](
                        coin_type=coin_type, address=int(path.rsplit('/', 1)[-1])
                    )
                )
            address = hdwallet.address()
            label = get_derivation_chains().get(derivation_type, {}).get('name', derivation_type)
            
            return DerivedAddress(
                path=path,
                address=address,
                label=label,
                chain_type=derivation_type
            )
        except Exception:
            return None
    
    def _derive_native(
        self, 
        mnemonic: str, 
        derivation_type: str, 
        count: int,
        passphrase: str = ''
    ) -> List[DerivedAddress]:
        addresses = []
        paths = get_derivation_paths()
        
        import hashlib
        import hmac
        
        salt = 'mnemonic' + passphrase
        iterations = 2048
        
        try:
            derived_key = hashlib.pbkdf2_hmac(
                'sha512',
                mnemonic.encode('utf-8'),
                salt.encode('utf-8'),
                iterations
            )
            
            master_key = derived_key[:64]
            master_chain_code = derived_key[32:]
            
            for i in range(count):
                address = self._derive_single_address(
                    master_key, 
                    master_chain_code, 
                    f"m/44'/0'/{i}",
                    derivation_type
                )
                if address:
                    addresses.append(DerivedAddress(
                        path=f"m/44'/0'/{i}",
                        address=address,
                        label=derivation_type,
                        chain_type=derivation_type
                    ))
        except Exception:
            pass
        
        return addresses
    
    def _derive_single_address(
        self,
        master_key: bytes,
        chain_code: bytes,
        path: str,
        derivation_type: str
    ) -> str:
        if derivation_type == 'ethereum':
            return self._derive_ethereum_address(master_key, path)
        elif derivation_type in ['bip44', 'bip49', 'bip84']:
            return self._derive_bitcoin_address(master_key, path, derivation_type)
        elif derivation_type in ['slip10', 'solana']:
            return self._derive_solana_address(master_key, path)
        return ''
    
    def _derive_ethereum_address(self, master_key: bytes, path: str) -> str:
        import ecdsa
        from ecdsa.curves import SECP256k1
        
        private_key = hashlib.sha256(master_key).digest()
        sk = ecdsa.SigningKey.from_string(private_key, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        pubkey = vk.to_string("uncompressed")
        address_hash = hashlib.sha3_256(pubkey).hexdigest()
        return '0x' + address_hash[24:]
    
    def _derive_bitcoin_address(self, master_key: bytes, path: str, derivation_type: str) -> str:
        return '1' + hashlib.sha256(master_key).hexdigest()[:34]
    
    def _derive_solana_address(self, master_key: bytes, path: str) -> str:
        import base58
        pubkey = hashlib.sha256(master_key).digest()[:32]
        return base58.b58encode(pubkey).decode()


class MultiChainExplorer:
    def __init__(self, derivation_engine: DerivationEngine):
        self.derivation = derivation_engine
        self.chain_clients = {}
    
    def get_evm_client(self, chain: str):
        config = get_chain_config(chain)
        if not config:
            raise ValueError(f"Unknown chain: {chain}")
        
        from web3 import Web3
        for rpc in config.rpc_endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(rpc))
                if w3.is_connected():
                    return w3
            except Exception:
                continue
        
        raise ConnectionError(f"Could not connect to any {chain} RPC")
    
    def get_balance(
        self, 
        chain: str, 
        address: str
    ) -> Optional[float]:
        try:
            w3 = self.get_evm_client(chain)
            balance_wei = w3.eth.get_balance(address)
            return w3.from_wei(balance_wei, 'ether')
        except Exception:
            return None
    
    def get_transactions(
        self,
        chain: str,
        address: str,
        limit: int = 100
    ) -> List[Dict]:
        try:
            w3 = self.get_evm_client(chain)
            config = get_chain_config(chain)
            
            transactions = []
            block = 0
            latest = w3.eth.block_number
            
            while block < latest and len(transactions) < limit:
                for tx_hash in w3.provider.make_request('eth_getBlocksByNumber', [hex(block), False])['result'] or []:
                    pass
                block += 100
            
            return transactions
        except Exception:
            return []
    
    def analyze_address(
        self,
        address: str,
        chains: Optional[List[str]] = None
    ) -> Dict:
        results = {
            'address': address,
            'chains': {},
            'timestamp': None
        }
        
        if chains is None:
            chains = list(CHAINS.keys())
        
        for chain in chains:
            try:
                balance = self.get_balance(chain, address)
                txs = self.get_transactions(chain, address)
                
                results['chains'][chain] = {
                    'balance': balance,
                    'transaction_count': len(txs),
                    'transactions': txs[:10]
                }
            except Exception as e:
                results['chains'][chain] = {
                    'error': str(e),
                    'balance': None,
                    'transaction_count': 0
                }
        
        return results


class SolanaExplorer:
    def __init__(self):
        self.rpc_endpoints = []
        self._load_endpoints()
    
    def _load_endpoints(self):
        self.rpc_endpoints = SOLANA_CONFIG['rpc_endpoints']
    
    def get_balance(self, address: str) -> Optional[int]:
        import json
        import urllib.request
        
        for rpc in self.rpc_endpoints:
            try:
                payload = json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getBalance",
                    "params": [address]
                }).encode('utf-8')
                
                req = urllib.request.Request(
                    rpc,
                    data=payload,
                    headers={'Content-Type': 'application/json'}
                )
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    result = json.loads(response.read().decode())
                    if 'result' in result:
                        return int(result['result']['value'])
            except Exception:
                continue
        
        return None
    
    def get_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        import json
        import urllib.request
        
        for rpc in self.rpc_endpoints:
            try:
                payload = json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getSignaturesForAddress",
                    "params": [address, {"limit": limit}]
                }).encode('utf-8')
                
                req = urllib.request.Request(
                    rpc,
                    data=payload,
                    headers={'Content-Type': 'application/json'}
                )
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    result = json.loads(response.read().decode())
                    if 'result' in result:
                        return result['result']
            except Exception:
                continue
        
        return []
    
    def analyze_address(self, address: str) -> Dict:
        balance_lamports = self.get_balance(address)
        transactions = self.get_transactions(address)
        
        return {
            'address': address,
            'balance_lamports': balance_lamports,
            'balance_sol': balance_lamports / 1_000_000_000 if balance_lamports else 0,
            'transaction_count': len(transactions),
            'transactions': transactions[:20],
            'timestamp': None
        }
