"""Secret-free recovery report persistence."""

import json
from datetime import datetime, timezone
from pathlib import Path

from .redaction import redact


def persist_report(report, directory="data/entropy/reports"):
    data = report.model_dump(mode="json") if hasattr(report, "model_dump") else report
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"recovery-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.json"
    path.write_text(json.dumps(redact(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
