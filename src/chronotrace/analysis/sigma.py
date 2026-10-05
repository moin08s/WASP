"""Native Sigma Rule Detection Engine for Forensic Timelines in WASP.

Supports loading and evaluating industry-standard Sigma YAML detection rules
directly over timeline events and EVTX event records. Ships with curated high-fidelity
DFIR rules (credential dumping, ransomware staging, LOLBin downloads, anti-forensics).
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from chronotrace.core.models import Event


# Safe YAML parsing fallback (pure Python minimal parser if pyyaml not installed)
try:
    import yaml
    HAS_YAML = True
except ImportError:
    yaml = None
    HAS_YAML = False


@dataclass
class SigmaMatch:
    """Represents an alert fired by a Sigma rule."""
    rule_id: str
    title: str
    level: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    mitre_tags: List[str]
    event_id: str
    timestamp_utc: str
    matched_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "description": self.description,
            "mitre_tags": self.mitre_tags,
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
            "matched_fields": self.matched_fields,
        }


BUILTIN_SIGMA_RULES: List[Dict[str, Any]] = [
    {
        "id": "sigma-proc-001",
        "title": "Credential Dumping via Mimikatz / LSASS Injection",
        "level": "CRITICAL",
        "description": "Detects execution of Mimikatz or LSASS memory scraping commands.",
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "detection": {
            "selection": {
                "any_field|contains": ["mimikatz", "sekurlsa", "lsadump", "procdump -ma lsass"]
            },
            "condition": "selection",
        },
    },
    {
        "id": "sigma-proc-002",
        "title": "Ransomware Volume Shadow Copy Deletion",
        "level": "CRITICAL",
        "description": "Inhibition of system recovery by deleting VSS shadows via vssadmin or wmic.",
        "tags": ["attack.impact", "attack.t1490"],
        "detection": {
            "selection": {
                "any_field|contains": [
                    "vssadmin delete shadows",
                    "wmic shadowcopy delete",
                    "wbadmin delete catalog",
                    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                ]
            },
            "condition": "selection",
        },
    },
    {
        "id": "sigma-proc-003",
        "title": "PowerShell Download Cradle & Hidden Execution",
        "level": "HIGH",
        "description": "Detects suspicious PowerShell execution with encoded commands or web downloads.",
        "tags": ["attack.execution", "attack.t1059.001"],
        "detection": {
            "selection": {
                "any_field|contains": [
                    "-enc ",
                    "-encodedcommand",
                    "downloadstring",
                    "invoke-webrequest",
                    "frombase64string",
                ]
            },
            "condition": "selection",
        },
    },
    {
        "id": "sigma-proc-004",
        "title": "LOLBin Ingress Tool Transfer via Certutil",
        "level": "HIGH",
        "description": "Detects certutil.exe used to download files from remote URLs.",
        "tags": ["attack.command_and_control", "attack.t1105"],
        "detection": {
            "selection": {
                "any_field|contains": ["certutil -urlcache", "certutil.exe -urlcache"]
            },
            "condition": "selection",
        },
    },
    {
        "id": "sigma-log-005",
        "title": "Windows Security Event Log Cleared (Anti-Forensics)",
        "level": "CRITICAL",
        "description": "Detects Event ID 1102 (audit log cleared) or wevtutil cl execution.",
        "tags": ["attack.defense_evasion", "attack.t1070.001"],
        "detection": {
            "selection": {
                "any_field|contains": ["wevtutil cl", "clear-eventlog", "eventid 1102", "1102"]
            },
            "condition": "selection",
        },
    },
    {
        "id": "sigma-proc-006",
        "title": "Persistence via Scheduled Task Creation",
        "level": "MEDIUM",
        "description": "Detects schtasks command creating persistent persistence hooks.",
        "tags": ["attack.persistence", "attack.t1053.005"],
        "detection": {
            "selection": {
                "any_field|contains": ["schtasks /create", "schtasks.exe /create"]
            },
            "condition": "selection",
        },
    },
]


class SigmaRuleEngine:
    """Evaluates Sigma-compatible detection rules against forensic events."""

    def __init__(self, custom_rule_dirs: Optional[List[Path]] = None):
        self.rules: List[Dict[str, Any]] = list(BUILTIN_SIGMA_RULES)
        if custom_rule_dirs:
            for d in custom_rule_dirs:
                self.load_directory(d)

    def load_directory(self, dir_path: str | Path) -> int:
        """Load .yml / .yaml Sigma rules from a directory."""
        p = Path(dir_path)
        if not p.is_dir():
            return 0
        loaded = 0
        for f in p.glob("**/*.y*ml"):
            if self.load_file(f):
                loaded += 1
        return loaded

    def load_file(self, file_path: Path) -> bool:
        """Parse and load a single Sigma rule file."""
        try:
            content = file_path.read_text(encoding="utf-8")
            if HAS_YAML:
                data = yaml.safe_load(content)
            else:
                # Basic key-value parser for simple YAML rules
                data = self._simple_yaml_parse(content)

            if isinstance(data, dict) and "detection" in data:
                self.rules.append(data)
                return True
        except Exception:
            pass
        return False

    def _simple_yaml_parse(self, text: str) -> Dict[str, Any]:
        """Rudimentary fallback parser for standard Sigma rule fields."""
        res: Dict[str, Any] = {"tags": []}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k in ("title", "id", "level", "description"):
                    res[k] = v
        return res

    def _event_to_searchable_strings(self, event: Event) -> Dict[str, str]:
        """Flatten event fields into searchable strings."""
        path_str = (event.object.path or "").lower()
        search_map: Dict[str, str] = {
            "action": event.action.lower(),
            "path": path_str,
            "user": (event.user or "").lower(),
            "event_id": event.event_id.lower(),
        }
        raw = event.raw or {}
        raw_text_parts = [event.action, path_str, (event.user or "").lower()]
        for k, v in raw.items():
            str_v = str(v).lower()
            search_map[k.lower()] = str_v
            raw_text_parts.append(str_v)

        search_map["any_field"] = " ".join(raw_text_parts)
        return search_map

    def _matches_rule(self, rule: Dict[str, Any], search_map: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Evaluate if event search map satisfies the rule selection condition."""
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})
        matched_fields: Dict[str, Any] = {}

        if not selection:
            return None

        # Check each condition in selection
        for field_spec, criteria in selection.items():
            field_name, *modifier = field_spec.split("|")
            field_name = field_name.strip().lower()
            mod = modifier[0].strip().lower() if modifier else "exact"

            val_in_event = search_map.get(field_name, search_map.get("any_field", ""))

            if isinstance(criteria, list):
                # Any match in list
                matched = False
                for term in criteria:
                    term_str = str(term).lower()
                    if mod == "contains" and term_str in val_in_event:
                        matched = True
                        matched_fields[field_spec] = term_str
                        break
                    elif mod == "exact" and term_str == val_in_event:
                        matched = True
                        matched_fields[field_spec] = term_str
                        break
                    elif mod == "endswith" and val_in_event.endswith(term_str):
                        matched = True
                        matched_fields[field_spec] = term_str
                        break
                if not matched:
                    return None
            else:
                criteria_str = str(criteria).lower()
                if mod == "contains" and criteria_str in val_in_event:
                    matched_fields[field_spec] = criteria_str
                elif mod == "exact" and criteria_str == val_in_event:
                    matched_fields[field_spec] = criteria_str
                elif mod == "endswith" and val_in_event.endswith(criteria_str):
                    matched_fields[field_spec] = criteria_str
                else:
                    return None

        return matched_fields

    def scan_events(self, events: List[Event]) -> List[SigmaMatch]:
        """Scan a list of timeline events against all active Sigma rules."""
        matches: List[SigmaMatch] = []

        for ev in events:
            search_map = self._event_to_searchable_strings(ev)
            for rule in self.rules:
                matched = self._matches_rule(rule, search_map)
                if matched is not None:
                    matches.append(
                        SigmaMatch(
                            rule_id=rule.get("id", "SIGMA-RULE"),
                            title=rule.get("title", "Sigma Alert"),
                            level=rule.get("level", "MEDIUM").upper(),
                            description=rule.get("description", ""),
                            mitre_tags=rule.get("tags", []),
                            event_id=ev.event_id,
                            timestamp_utc=ev.timestamp_utc,
                            matched_fields=matched,
                        )
                    )

        return matches
