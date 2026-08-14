"""Bitcoin Core public wallet/dump ingestion with legacy/descriptor distinction."""

import json
import sqlite3
from pathlib import Path
import re

from .base import ArtifactInspection, ArtifactPasswordResult


class BitcoinCoreArtifactAdapter:
    adapter_id = "bitcoin-core-wallet"

    def _bytes(self, artifact):
        if isinstance(artifact, bytes): return artifact
        if isinstance(artifact, str): return Path(artifact).read_bytes()
        raise ValueError("Bitcoin Core artifact must be a local file")

    def _text(self, artifact):
        if isinstance(artifact, str):
            path = Path(artifact)
            if path.suffix in {".dump", ".txt"}: return path.read_text(errors="replace")
        if isinstance(artifact, bytes): return artifact.decode(errors="replace")
        return ""

    def inspect(self, artifact):
        try:
            text = self._text(artifact)
            if "# Wallet dump created by Bitcoin Core" in text or "# Wallet dump" in text:
                return ArtifactInspection(self.adapter_id, True, False, public_metadata=self._dump_metadata(text))
            raw = self._bytes(artifact)
            if raw.startswith(b"SQLite format 3"):
                return ArtifactInspection(self.adapter_id, True, False, public_metadata={"wallet_format": "descriptor-sqlite", **self._sqlite_metadata(artifact)})
            if b"Berkeley DB" in raw[:4096] or Path(str(artifact)).name == "wallet.dat":
                return ArtifactInspection(self.adapter_id, True, True, public_metadata={"wallet_format": "legacy-berkeley-db", "migration": "Use Bitcoin Core migratewallet semantics; no private records are rewritten"})
        except Exception:
            pass
        return ArtifactInspection(self.adapter_id, False, False)

    def _dump_metadata(self, text):
        addresses = []
        for line in text.splitlines():
            if line and not line.startswith("#"):
                parts = line.split()
                if parts: addresses.append(parts[0])
        return {"wallet_format": "dumpwallet", "known_addresses": addresses[:500], "record_count": len(addresses), "private_records_present": any("label=" in line for line in text.splitlines())}

    def _sqlite_metadata(self, artifact):
        db = sqlite3.connect(f"file:{Path(artifact).resolve()}?mode=ro", uri=True)
        try:
            tables = [row[0] for row in db.execute("select name from sqlite_master where type='table'")]
            descriptors = []
            if "descriptors" in tables:
                descriptors = [row[0] for row in db.execute("select descriptor from descriptors") if row and row[0]]
            return {"tables": tables, "descriptors": descriptors[:100], "descriptor_count": len(descriptors)}
        finally: db.close()

    def estimate_work(self, artifact): return {"kdf": "bitcoin-core-native", "external_process_required": True}
    def extract_public_evidence(self, artifact): return self.inspect(artifact).public_metadata
    def verify_password_candidate(self, artifact, password): return ArtifactPasswordResult(False, error="Bitcoin Core private-key validation requires isolated Core wallet tooling", estimated_work=self.estimate_work(artifact))
    def recover(self, artifact, password): return self.verify_password_candidate(artifact, password)
