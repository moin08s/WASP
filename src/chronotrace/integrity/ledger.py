"""Append-only, hash-chained Chain of Custody Ledger."""

from __future__ import annotations
import datetime
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from chronotrace.core.errors import IntegrityError

GENESIS_HASH = "0" * 64


class CustodyLedger:
    """Manages the cryptographically linked chain of custody log."""

    def __init__(self, ledger_file: str | Path, hmac_key: Optional[bytes] = None):
        self.ledger_file = Path(ledger_file)
        self.hmac_key = hmac_key
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)

    def _get_last_entry(self) -> Optional[Dict[str, Any]]:
        if not self.ledger_file.exists() or self.ledger_file.stat().st_size == 0:
            return None
        last_line = ""
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    last_line = line_str
        if not last_line:
            return None
        return json.loads(last_line)

    def append_event(
        self,
        event_type: str,
        actor: str,
        payload: Dict[str, Any],
        timestamp_utc: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a new audited event to the hash-chained custody ledger."""
        last_entry = self._get_last_entry()
        seq = 1 if last_entry is None else last_entry["seq"] + 1
        prev_hash = GENESIS_HASH if last_entry is None else last_entry["entry_hash"]

        if not timestamp_utc:
            timestamp_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        entry_data = {
            "seq": seq,
            "timestamp_utc": timestamp_utc,
            "actor": actor,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev_hash,
        }

        # Canonical entry hash calculation
        canonical_str = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        entry_data["entry_hash"] = entry_hash

        if self.hmac_key:
            entry_data["signature"] = hmac.new(
                self.hmac_key, entry_hash.encode("utf-8"), hashlib.sha256
            ).hexdigest()

        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_data, sort_keys=True) + "\n")

        return entry_data

    def verify_ledger(self) -> Tuple[bool, int, List[str]]:
        """
        Replay and cryptographically verify the integrity of the ledger.
        Returns: (is_valid, record_count, errors)
        """
        if not self.ledger_file.exists():
            return True, 0, []

        records: List[Dict[str, Any]] = []
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                clean = line.strip()
                if clean:
                    try:
                        records.append(json.loads(clean))
                    except Exception as e:
                        return False, len(records), [f"Line {idx}: Corrupted JSON: {e}"]

        errors: List[str] = []
        expected_prev_hash = GENESIS_HASH

        for idx, rec in enumerate(records, 1):
            if rec.get("seq") != idx:
                errors.append(f"Seq mismatch at line {idx}: expected {idx}, found {rec.get('seq')}")

            if rec.get("prev_hash") != expected_prev_hash:
                errors.append(
                    f"Hash chain broken at seq {idx}: expected prev_hash {expected_prev_hash}, found {rec.get('prev_hash')}"
                )

            # Recompute entry hash
            core_data = {
                "seq": rec["seq"],
                "timestamp_utc": rec["timestamp_utc"],
                "actor": rec["actor"],
                "event_type": rec["event_type"],
                "payload": rec["payload"],
                "prev_hash": rec["prev_hash"],
            }
            canonical_str = json.dumps(core_data, sort_keys=True, separators=(",", ":"))
            calc_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

            if calc_hash != rec.get("entry_hash"):
                errors.append(
                    f"Entry hash mismatch at seq {idx}: calculated {calc_hash}, recorded {rec.get('entry_hash')}"
                )

            if self.hmac_key and "signature" in rec:
                calc_sig = hmac.new(
                    self.hmac_key, rec["entry_hash"].encode("utf-8"), hashlib.sha256
                ).hexdigest()
                if calc_sig != rec["signature"]:
                    errors.append(f"Invalid HMAC signature at seq {idx}")

            expected_prev_hash = rec.get("entry_hash", "")

        return len(errors) == 0, len(records), errors

    def get_entries(self) -> List[Dict[str, Any]]:
        """Read all entries from ledger."""
        if not self.ledger_file.exists():
            return []
        entries = []
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    entries.append(json.loads(line_str))
        return entries
