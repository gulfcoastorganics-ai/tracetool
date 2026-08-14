"""Sanitized report persistence."""

import json
from datetime import datetime, timezone
from pathlib import Path


def sanitize_report(report):
    data = report.model_dump(mode="json") if hasattr(report, "model_dump") else dict(report)
    forbidden = {"mnemonic", "entropy_hex", "entropy_bytes", "private_key", "seed", "seed_phrase", "passphrase", "xprv"}

    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if key.lower() not in forbidden and not any(item_name in key.lower() for item_name in ("private_key", "mnemonic", "passphrase", "entropy_bytes", "xprv"))}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    return clean(data)


def persist_report(report, directory: str | Path = "data/entropy/reports"):
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"assurance-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.json"
    path.write_text(json.dumps(sanitize_report(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
