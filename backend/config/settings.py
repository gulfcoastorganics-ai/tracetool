import os
from dataclasses import dataclass
from typing import List, Dict, Optional
from functools import lru_cache

@dataclass
class ChainConfig:
    name: str
    chain_id: int
    rpc_endpoints: List[str]
    explorer_url: str
    api_base: str
    native_currency: str

CHAINS = {
    'ethereum': ChainConfig(
        name='Ethereum',
        chain_id=1,
        rpc_endpoints=[
            'https://cloudflare-eth.com',
            'https://eth.drpc.org',
            'https://walrus.ocf.berkeley.edu:8545',
        ],
        explorer_url='https://etherscan.io',
        api_base='https://api.etherscan.io/api',
        native_currency='ETH'
    ),
    'base': ChainConfig(
        name='Base',
        chain_id=8453,
        rpc_endpoints=[
            'https://base.drpc.org',
            'https://mainnet.base.org',
            'https://base-rpc.riselabs.com',
        ],
        explorer_url='https://basescan.org',
        api_base='https://api.basescan.org/api',
        native_currency='ETH'
    ),
    'bsc': ChainConfig(
        name='Binance Smart Chain',
        chain_id=56,
        rpc_endpoints=[
            'https://bsc-dataseed.binance.org',
            'https://bsc-dataseed1.defibit.io',
            'https://bsc-dataseed4.frankstau.uk',
            'https://bsc-dataseed.pnodes.dev',
        ],
        explorer_url='https://bscscan.com',
        api_base='https://api.bscscan.com/api',
        native_currency='BNB'
    ),
    'polygon': ChainConfig(
        name='Polygon',
        chain_id=137,
        rpc_endpoints=[
            'https://polygon.drpc.org',
            'https://rpc-mainnet.maticvigil.com',
            'https://spuru-rpc.public.bloXroute.app',
        ],
        explorer_url='https://polygonscan.com',
        api_base='https://api.polygonscan.com/api',
        native_currency='MATIC'
    )
}

SOLANA_CONFIG = {
    'rpc_endpoints': [
        'https://api.mainnet-beta.solana.com',
        'https://solana-mainnet.g.alchemy.com/v2/demo',
        'https://sunny-jolly-solana-regional.data.yale.edu',
        'https://solana-api.projectserum.com',
    ],
    'explorers': [
        'https://solscan.io',
        'https://explorer.solana.com',
        'https://solana.fm',
    ],
    'api_endpoints': [
        'https://public-api.solfma.xyz',
        'https://api.mainnet-beta.solana.com',
    ]
}

BITCOIN_CONFIG = {
    'rpc_host': os.getenv('BTC_RPC_HOST', 'localhost'),
    'rpc_port': int(os.getenv('BTC_RPC_PORT', '8332')),
    'rpc_user': os.getenv('BTC_RPC_USER', ''),
    'rpc_password': os.getenv('BTC_RPC_PASSWORD', ''),
    'blockchain_path': os.getenv('BTC_BLOCKCHAIN_PATH', ''),
    'peer_mode': True
}

DERIVATION_PATHS = {
    'bip44': "m/44'/0'/0'",
    'bip49': "m/49'/0'/0'",
    'bip84': "m/84'/0'/0'",
    'slip10': "m/44'/501'/0'",
    'ethereum': "m/44'/60'/0'",
    'solana': "m/44'/501'/0'"
}

DERIVATION_CHAINS = {
    'bip44': {'name': 'Bitcoin Legacy', 'address_prefix': '1'},
    'bip49': {'name': 'Bitcoin SegWit', 'address_prefix': '3'},
    'bip84': {'name': 'Bitcoin Native SegWit', 'address_prefix': 'bc1'},
    'slip10': {'name': 'Solana', 'address_prefix': ''},
    'ethereum': {'name': 'EVM Chains', 'address_prefix': '0x'},
}

@lru_cache(maxsize=1)
def get_chain_config(chain_name: str) -> Optional[ChainConfig]:
    return CHAINS.get(chain_name)

def get_all_chains() -> List[str]:
    return list(CHAINS.keys())

def get_evm_chains() -> List[str]:
    return list(CHAINS.keys())

def get_solana_config() -> Dict:
    return SOLANA_CONFIG.copy()

def get_bitcoin_config() -> Dict:
    return BITCOIN_CONFIG.copy()

def get_derivation_paths() -> Dict[str, str]:
    return DERIVATION_PATHS.copy()

def get_derivation_chains() -> Dict[str, Dict]:
    return DERIVATION_CHAINS.copy()

def get_cors_origins() -> List[str]:
    """Return explicit browser origins allowed to call the local API.

    Wildcard CORS is intentionally not the default because credentialed requests
    must never be paired with an unrestricted origin policy. Deployments can set
    CHAIN_TRACE_CORS_ORIGINS to a comma-separated allowlist.
    """
    raw = os.getenv(
        'CHAIN_TRACE_CORS_ORIGINS',
        'http://127.0.0.1:5173,http://localhost:5173',
    )
    return [origin.strip() for origin in raw.split(',') if origin.strip()]
