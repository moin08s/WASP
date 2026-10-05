"""Redaction engine for scrubbed reporting disclosures."""

from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set
from chronotrace.core.models import Event


class RedactionEngine:
    """Applies privacy redaction to events and strings before report rendering."""

    def __init__(self, redact_fields: Set[str], case_report_dir: Path):
        self.redact_fields = {f.lower().strip() for f in redact_fields}
        self.report_dir = case_report_dir
        self.map_file = self.report_dir / ".redaction_map.json"
        self._map: Dict[str, str] = {}
        self._counter = 1

    def _pseudonym(self, category: str, original: str) -> str:
        """Create or lookup consistent pseudonym for an original sensitive value."""
        if not original or original in ("UNKNOWN", "SYSTEM", "N/A"):
            return original
        key = f"{category}:{original}"
        if key not in self._map:
            pseudo = f"[{category.upper()}_{self._counter:03d}]"
            self._map[key] = pseudo
            self._counter += 1
        return self._map[key]

    def redact_event(self, event: Event) -> Event:
        """Return a copy of the event with configured sensitive fields redacted."""
        dumped = event.model_dump()

        if "usernames" in self.redact_fields and dumped.get("user"):
            dumped["user"] = self._pseudonym("user", dumped["user"])

        if "paths" in self.redact_fields and dumped.get("object", {}).get("path"):
            original_path = dumped["object"]["path"]
            parts = original_path.replace("\\", "/").split("/")
            # Redact user directory part e.g. /Users/alice/ or C:/Users/alice/
            redacted_parts = []
            for i, p in enumerate(parts):
                if i > 0 and parts[i - 1].lower() in ("users", "home"):
                    redacted_parts.append(self._pseudonym("user_folder", p))
                else:
                    redacted_parts.append(p)
            dumped["object"]["path"] = "/".join(redacted_parts)

        if "ips" in self.redact_fields and dumped.get("object", {}).get("path"):
            dumped["object"]["path"] = re.sub(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                lambda m: self._pseudonym("ip", m.group(0)),
                dumped["object"]["path"]
            )

        # Clear raw dictionary from sensitive data in disclosed report
        if "raw" in self.redact_fields:
            dumped["raw"] = {"redacted": True}

        return Event.model_validate(dumped)

    def save_mapping(self) -> None:
        """Save reverse de-redaction mapping file securely."""
        self.report_dir.mkdir(parents=True, exist_ok=True)
        with open(self.map_file, "w", encoding="utf-8") as f:
            json.dump(self._map, f, indent=2, sort_keys=True)
