"""Forensic YARA and Threat Pattern Rule Engine for ChronoTrace.

Evaluates evidence files and reconstructed timeline events against YARA rules
and curated DFIR threat patterns (LOLBins, Ransomware, Credential Dumping,
Persistence, and Anti-Forensics).
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from chronotrace.core.models import Event

# Check if native yara-python is available
try:
    import yara
    HAS_YARA = True
except ImportError:
    yara = None
    HAS_YARA = False


DEFAULT_YARA_RULES = """
rule Mimikatz_Credentials {
    meta:
        description = "Detects Mimikatz credential dumping signatures"
        severity = "CRITICAL"
        mitre = "T1003"
    strings:
        $s1 = "sekurlsa" nocase
        $s2 = "lsadump" nocase
        $s3 = "wdigest" nocase
        $s4 = "kerberos" nocase
        $s5 = "mimikatz" nocase
    condition:
        2 of ($s1, $s2, $s3, $s4, $s5)
}

rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Detects VSS shadow copy deletion and recovery inhibition"
        severity = "HIGH"
        mitre = "T1490"
    strings:
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wmic shadowcopy delete" nocase
        $cmd3 = "bcedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $cmd4 = "wbadmin delete catalog" nocase
    condition:
        any of them
}

rule Suspicious_LOLBin_Execution {
    meta:
        description = "Detects living-off-the-land binary (LOLBin) abuse"
        severity = "HIGH"
        mitre = "T1059"
    strings:
        $ps1 = "powershell" nocase
        $enc = "-enc " nocase
        $b64 = "FromBase64String" nocase
        $cu = "certutil -urlcache" nocase
        $ms = "mshta http" nocase
    condition:
        ($ps1 and ($enc or $b64)) or $cu or $ms
}

rule AntiForensics_Log_Clearing {
    meta:
        description = "Detects Windows Event Log clearing commands"
        severity = "HIGH"
        mitre = "T1070"
    strings:
        $wevt1 = "wevtutil cl" nocase
        $wevt2 = "Clear-EventLog" nocase
    condition:
        any of them
}
"""

# Pure-python fallback rules
BUILTIN_PATTERN_RULES: List[Dict[str, Any]] = [
    {
        "name": "Mimikatz_Credentials",
        "description": "Mimikatz / LSASS credential dumping pattern",
        "severity": "CRITICAL",
        "mitre": "T1003",
        "patterns": [r"sekurlsa", r"lsadump", r"mimikatz", r"procdump.*lsass"],
        "min_match": 1,
    },
    {
        "name": "Ransomware_ShadowCopy_Deletion",
        "description": "VSS shadow copy deletion & inhibition of recovery",
        "severity": "HIGH",
        "mitre": "T1490",
        "patterns": [r"vssadmin.*delete.*shadows", r"wmic.*shadowcopy.*delete", r"wbadmin.*delete.*catalog"],
        "min_match": 1,
    },
    {
        "name": "Suspicious_LOLBin_Execution",
        "description": "Suspicious PowerShell encoded execution or certutil download",
        "severity": "HIGH",
        "mitre": "T1059.001",
        "patterns": [r"powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}", r"certutil.*-urlcache", r"mshta.*http"],
        "min_match": 1,
    },
    {
        "name": "AntiForensics_Log_Clearing",
        "description": "Security or System event log wiping",
        "severity": "HIGH",
        "mitre": "T1070.001",
        "patterns": [r"wevtutil\s+cl", r"clear-eventlog"],
        "min_match": 1,
    },
    {
        "name": "Ransomware_Extension_Alert",
        "description": "Known ransomware extension or ransom note creation",
        "severity": "CRITICAL",
        "mitre": "T1486",
        "patterns": [r"\.(locked|crypto|crypt|enc|lockbit|blackcat|wncry)$", r"(readme|how_to_decrypt|restore_files)\.(txt|hta|html)$"],
        "min_match": 1,
    },
    {
        "name": "Persistence_Run_Key",
        "description": "Persistence via Windows Registry Run or Startup folder",
        "severity": "MEDIUM",
        "mitre": "T1547.001",
        "patterns": [r"CurrentVersion\\Run", r"Start Menu\\Programs\\Startup"],
        "min_match": 1,
    },
]


@dataclass
class AlertFinding:
    """Represents a threat, IOC, or rule match finding."""
    rule_name: str
    severity: str
    mitre_technique: str
    description: str
    target: str
    matched_patterns: List[str]
    event_id: Optional[str] = None
    timestamp_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "target": self.target,
            "matched_patterns": self.matched_patterns,
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
        }


class RuleEngine:
    """
    Forensic rule scanner applying YARA and threat pattern matching
    to evidence files and reconstructed timeline events.
    """

    def __init__(self, custom_yara_path: Optional[str | Path] = None):
        self.yara_compiled = None
        self.has_yara = HAS_YARA

        if self.has_yara and yara is not None:
            try:
                if custom_yara_path and Path(custom_yara_path).exists():
                    self.yara_compiled = yara.compile(filepath=str(custom_yara_path))
                else:
                    self.yara_compiled = yara.compile(source=DEFAULT_YARA_RULES)
            except Exception:
                self.yara_compiled = None

    def scan_text(self, text: str, target_name: str = "text") -> List[AlertFinding]:
        """Scan a string or text payload against rules."""
        findings: List[AlertFinding] = []

        # 1. YARA scan if available
        if self.yara_compiled:
            try:
                matches = self.yara_compiled.match(data=text.encode("utf-8", errors="ignore"))
                for m in matches:
                    findings.append(AlertFinding(
                        rule_name=m.rule,
                        severity=m.meta.get("severity", "HIGH"),
                        mitre_technique=m.meta.get("mitre", "T1059"),
                        description=m.meta.get("description", f"YARA rule {m.rule} matched"),
                        target=target_name,
                        matched_patterns=[s.identifier for s in getattr(m, "strings", [])][:5],
                    ))
            except Exception:
                pass

        # 2. Pure-Python regex pattern rules (complements or acts as fallback)
        for rule in BUILTIN_PATTERN_RULES:
            # Skip duplicate if YARA already matched same rule name
            if any(f.rule_name == rule["name"] for f in findings):
                continue

            matched = []
            for pat in rule["patterns"]:
                if re.search(pat, text, re.IGNORECASE):
                    matched.append(pat)

            if len(matched) >= rule.get("min_match", 1):
                findings.append(AlertFinding(
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre_technique=rule["mitre"],
                    description=rule["description"],
                    target=target_name,
                    matched_patterns=matched,
                ))

        return findings

    def scan_events(self, events: List[Event]) -> List[AlertFinding]:
        """
        Scan reconstructed timeline events. Mutates matching events by adding
        ALERT and THREAT tags, and returns all detected findings.
        """
        all_findings: List[AlertFinding] = []

        for ev in events:
            # Form searchable text corpus from event attributes
            elements = [
                ev.object.path or "",
                ev.object.path_norm or "",
                ev.rationale or "",
                ev.action or "",
                json.dumps(ev.raw),
            ]
            corpus = " ".join(elements)

            findings = self.scan_text(corpus, target_name=ev.object.path or ev.event_id)
            for f in findings:
                f.event_id = ev.event_id
                f.timestamp_utc = ev.timestamp_utc

                # Tag event
                if "ALERT" not in ev.tags:
                    ev.tags.append("ALERT")
                threat_tag = f"THREAT:{f.rule_name.upper()}"
                if threat_tag not in ev.tags:
                    ev.tags.append(threat_tag)
                sev_tag = f"SEVERITY:{f.severity.upper()}"
                if sev_tag not in ev.tags:
                    ev.tags.append(sev_tag)

                # Add warning
                ev.warnings.append(f"Threat detected [{f.severity}] {f.rule_name}: {f.description}")

                all_findings.append(f)

        return all_findings

    def scan_file(self, file_path: str | Path) -> List[AlertFinding]:
        """Scan a binary or text file using YARA rules."""
        path = Path(file_path)
        if not path.is_file():
            return []

        findings: List[AlertFinding] = []
        try:
            with open(path, "rb") as f:
                data = f.read(1048576)  # Read up to 1MB
        except Exception:
            return []

        if not data:
            return []

        # 1. YARA buffer scan
        if self.yara_compiled:
            try:
                matches = self.yara_compiled.match(data=data)
                for m in matches:
                    findings.append(AlertFinding(
                        rule_name=m.rule,
                        severity=m.meta.get("severity", "HIGH"),
                        mitre_technique=m.meta.get("mitre", "T1059"),
                        description=m.meta.get("description", f"YARA rule {m.rule} matched in file"),
                        target=str(path),
                        matched_patterns=[s.identifier for s in getattr(m, "strings", [])][:5],
                    ))
            except Exception:
                pass

        # 2. Text fallback scan
        try:
            text = data.decode("utf-8", errors="ignore")
            text_findings = self.scan_text(text, target_name=str(path))
            for tf in text_findings:
                if not any(f.rule_name == tf.rule_name for f in findings):
                    findings.append(tf)
        except Exception:
            pass

        return findings
