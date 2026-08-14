"""Bounded standard derivation explorer using the existing hdwallet dependency."""

from dataclasses import dataclass
from typing import Iterable, List

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import Bitcoin, Ethereum, Solana
from hdwallet.derivations import BIP44Derivation, BIP49Derivation, BIP84Derivation, BIP86Derivation
from hdwallet.mnemonics import BIP39Mnemonic


MAX_DERIVATIONS = 180


@dataclass
class DerivationCandidate:
    network: str
    path: str
    address: str


def _wallet(mnemonic: str, passphrase: str, cryptocurrency):
    return HDWallet(cryptocurrency=cryptocurrency, passphrase=passphrase).from_mnemonic(BIP39Mnemonic(mnemonic))


def _bitcoin_candidates(mnemonic: str, passphrase: str, account_start: int, account_count: int, index_start: int, index_count: int, purposes=None):
    derivations = [
        ("44", "m/44'/{account}'/{account}/0/{index}", BIP44Derivation),
        ("49", "m/49'/{account}'/{account}/0/{index}", BIP49Derivation),
        ("84", "m/84'/{account}'/{account}/0/{index}", BIP84Derivation),
        ("86", "m/86'/{account}'/{account}/0/{index}", BIP86Derivation),
    ]
    # The display path is canonicalized below; hdwallet receives coin_type separately.
    results = []
    if purposes:
        derivations = [item for item in derivations if int(item[0]) in purposes]
    for purpose, _, klass in derivations:
        for account in range(account_start, account_start + account_count):
            for index in range(index_start, index_start + index_count):
                wallet = _wallet(mnemonic, passphrase, Bitcoin)
                wallet.from_derivation(klass(coin_type=0, account=account, change=0, address=index))
                results.append(DerivationCandidate("bitcoin", f"m/{purpose}'/0'/{account}'/0/{index}", wallet.address()))
    return results


def _ethereum_candidates(mnemonic: str, passphrase: str, account_start: int, account_count: int, index_start: int, index_count: int):
    results = []
    for account in range(account_start, account_start + account_count):
        for index in range(index_start, index_start + index_count):
            variants = [
                (f"m/44'/60'/{account}'/0/{index}", BIP44Derivation(coin_type=60, account=account, change=0, address=index)),
                *([(f"m/44'/60'/0'/{index}", BIP44Derivation(coin_type=60, account=0, change=index, address=0))] if index in (0, 1) else []),
                (f"m/44'/60'/{account}'/0/0", BIP44Derivation(coin_type=60, account=account, change=0, address=0)),
            ]
            for path, derivation in variants:
                wallet = _wallet(mnemonic, passphrase, Ethereum)
                wallet.from_derivation(derivation)
                results.append(DerivationCandidate("ethereum", path, wallet.address()))
    return results


def _solana_candidates(mnemonic: str, passphrase: str, account_start: int, account_count: int, index_start: int, index_count: int):
    results = []
    for account in range(account_start, account_start + min(account_count, index_count)):
        # Solana wallet conventions commonly expose the account index as i in
        # m/44'/501'/i'/0'. Keep this exact path visible to the owner.
        wallet = _wallet(mnemonic, passphrase, Solana)
        wallet.from_derivation(BIP44Derivation(coin_type=501, account=account, change=0, address=0))
        results.append(DerivationCandidate("solana", f"m/44'/501'/{account}'/0'", wallet.address()))
    return results


def explore_derivations(mnemonic: str, *, networks: Iterable[str], passphrase: str = "", account_start=0, account_count=1, index_start=0, index_count=5, bitcoin_purposes=None) -> List[DerivationCandidate]:
    requested = account_count * index_count * 7
    if requested > MAX_DERIVATIONS:
        raise ValueError(f"derivation exploration exceeds local limit of {MAX_DERIVATIONS} candidates")
    candidates = []
    for network in networks:
        if network in ("bitcoin", "btc"):
            candidates.extend(_bitcoin_candidates(mnemonic, passphrase, account_start, account_count, index_start, index_count, bitcoin_purposes))
        elif network in ("ethereum", "evm", "eth"):
            candidates.extend(_ethereum_candidates(mnemonic, passphrase, account_start, account_count, index_start, index_count))
        elif network == "solana":
            candidates.extend(_solana_candidates(mnemonic, passphrase, account_start, account_count, index_start, index_count))
        else:
            raise ValueError(f"unsupported recovery network: {network}")
    return candidates


def derive_one(mnemonic: str, *, network: str, path: str, passphrase: str = "") -> DerivationCandidate:
    # Use the same bounded standard path constructors for address verification.
    if network in ("ethereum", "evm", "eth"):
        parts = path.replace("'", "").split("/")
        account, change, index = int(parts[3]), int(parts[4]), int(parts[5]) if len(parts) > 5 else 0
        wallet = _wallet(mnemonic, passphrase, Ethereum)
        wallet.from_derivation(BIP44Derivation(coin_type=60, account=account, change=change, address=index))
        return DerivationCandidate("ethereum", path, wallet.address())
    if network in ("bitcoin", "btc"):
        purpose = int(path.split("/")[1].replace("'", ""))
        parts = path.replace("'", "").split("/")
        account, change, index = int(parts[3]), int(parts[4]), int(parts[5])
        klass = {44: BIP44Derivation, 49: BIP49Derivation, 84: BIP84Derivation, 86: BIP86Derivation}.get(purpose)
        if klass is None:
            raise ValueError("unsupported Bitcoin derivation purpose")
        wallet = _wallet(mnemonic, passphrase, Bitcoin)
        wallet.from_derivation(klass(coin_type=0, account=account, change=change, address=index))
        return DerivationCandidate("bitcoin", path, wallet.address())
    if network == "solana":
        parts = path.replace("'", "").split("/")
        account = int(parts[3])
        wallet = _wallet(mnemonic, passphrase, Solana)
        wallet.from_derivation(BIP44Derivation(coin_type=501, account=account, change=0, address=0))
        return DerivationCandidate("solana", path, wallet.address())
    raise ValueError(f"unsupported recovery network: {network}")
