"""Conservative wallet-specific derivation profiles.

Profiles encode common conventions, not claims that every version of a wallet
used one path. Matches are evidence-ranked and remain bounded by caller limits.
"""

from .models import WalletProfile

PROFILES = [
    WalletProfile(id="ledger-btc-segwit", name="Ledger Bitcoin SegWit", applications=["ledger", "ledger live"], networks=["bitcoin"], purposes=[84, 86], coin_type=0, change_branches=[0, 1], address_type="segwit", default_gap_limit=20, historical_quirks=["Account discovery normally follows external/change branches."]),
    WalletProfile(id="trezor-btc", name="Trezor Bitcoin", applications=["trezor", "trezor suite"], networks=["bitcoin"], purposes=[44, 49, 84], coin_type=0, change_branches=[0, 1], address_type="profile-dependent", default_gap_limit=20),
    WalletProfile(id="electrum-btc", name="Electrum Bitcoin", applications=["electrum"], networks=["bitcoin"], purposes=[44, 49, 84], coin_type=0, change_branches=[0, 1], address_type="profile-dependent", default_gap_limit=20, historical_quirks=["Wallet files and watch-only exports may reveal script type and derivation metadata."]),
    WalletProfile(id="metamask-evm", name="MetaMask EVM", applications=["metamask"], networks=["ethereum", "evm"], purposes=[44], coin_type=60, change_branches=[0], address_type="secp256k1", default_gap_limit=20),
    WalletProfile(id="trust-wallet-evm", name="Trust Wallet EVM", applications=["trust wallet", "trustwallet"], networks=["ethereum", "evm"], purposes=[44], coin_type=60, change_branches=[0], address_type="secp256k1", default_gap_limit=20),
    WalletProfile(id="phantom-solana", name="Phantom Solana", applications=["phantom"], networks=["solana"], purposes=[44], coin_type=501, change_branches=[0], address_type="ed25519", default_gap_limit=20),
    WalletProfile(id="exodus-multi", name="Exodus", applications=["exodus"], networks=["bitcoin", "ethereum", "solana"], purposes=[44, 49, 84], coin_type=0, change_branches=[0, 1], address_type="profile-dependent", default_gap_limit=20),
]


def all_profiles():
    return list(PROFILES)


def profile_matches(*, application=None, network=None, address_type=None):
    app = (application or "").lower()
    return [profile for profile in PROFILES if (not app or any(app in item for item in profile.applications)) and (not network or network in profile.networks) and (not address_type or address_type == profile.address_type)]


def get_profile(profile_id: str):
    return next((profile for profile in PROFILES if profile.id == profile_id), None)
