"""Evidence-ranked derivation path hypotheses."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PathHypothesis:
    network: str
    path_template: str
    score: float
    reasons: list[str]


def rank_path_hypotheses(*, network: str, wallet_application=None, creation_year=None, address_types=None, extended_key_type=None, descriptor=None, known_path=None):
    address_types = {item.lower() for item in (address_types or [])}
    app = (wallet_application or "").lower()
    result = []
    if known_path:
        return [PathHypothesis(network, known_path, 1000, ["owner-supplied derivation path"])]
    if network in ("bitcoin", "btc"):
        options = [(84, "native SegWit", 60), (49, "wrapped SegWit", 45), (44, "legacy", 30), (86, "Taproot", 25)]
        if descriptor and any(item in descriptor.lower() for item in ("multi(", "sortedmulti(", "wsh(")):
            options.extend([(48, "multisig account", 70), (45, "BIP45 shared multisig", 55)])
        if extended_key_type in {"zpub", "vpub"} or "segwit" in address_types:
            options = sorted(options, key=lambda item: 0 if item[0] == 84 else 1)
        if extended_key_type in {"ypub", "upub"} or "wrapped-segwit" in address_types:
            options = sorted(options, key=lambda item: 0 if item[0] == 49 else 1)
        for purpose, label, score in options:
            reasons = [label]
            if purpose in {45, 48}: reasons.append("multisig policy evidence")
            if "ledger" in app and purpose in {84, 86}: score += 20; reasons.append("Ledger profile")
            if "electrum" in app and purpose in {44, 49, 84}: score += 15; reasons.append("Electrum profile")
            if creation_year and creation_year < 2019 and purpose == 44: score += 10; reasons.append("creation era")
            result.append(PathHypothesis("bitcoin", f"m/{purpose}'/0'/{{account}}'/{{change}}/{{index}}", score, reasons))
    elif network in ("ethereum", "evm", "eth"):
        score = 70 if "meta" in app or "trust" in app else 50
        result.append(PathHypothesis("ethereum", "m/44'/60'/{account}'/0/{index}", score, ["BIP44 EVM account path"]))
        result.append(PathHypothesis("ethereum", "m/44'/60'/0'/{index}", score - 10, ["EVM change-branch variant"]))
    elif network == "solana":
        result.append(PathHypothesis("solana", "m/44'/501'/{account}'/0'", 70 if "phantom" in app else 50, ["Solana SLIP-0044 path"]))
    return sorted(result, key=lambda item: item.score, reverse=True)
