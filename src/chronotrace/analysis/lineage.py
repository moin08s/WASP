"""Process Lineage Tree Reconstruction Engine for WASP.

Reconstructs hierarchical process execution trees from Windows Event ID 4688,
Sysmon Event ID 1, and Linux process execution logs by linking Parent Process IDs
(PPID) to Child Process IDs (PID). Automatically flags suspicious process lineage
(e.g., Office applications spawning CMD/PowerShell, Web servers spawning shells).
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from chronotrace.core.models import Event


SUSPICIOUS_SPAWNS = [
    # (Parent pattern, Child pattern, Threat description)
    ("winword.exe", "cmd.exe", "Office macro spawning command interpreter"),
    ("winword.exe", "powershell.exe", "Office macro spawning PowerShell"),
    ("excel.exe", "cmd.exe", "Excel macro spawning command interpreter"),
    ("excel.exe", "powershell.exe", "Excel macro spawning PowerShell"),
    ("outlook.exe", "powershell.exe", "Outlook spawning PowerShell stager"),
    ("w3wp.exe", "cmd.exe", "Web shell: IIS worker spawning command prompt"),
    ("w3wp.exe", "powershell.exe", "Web shell: IIS worker spawning PowerShell"),
    ("powershell.exe", "vssadmin.exe", "PowerShell executing volume shadow deletion"),
    ("cmd.exe", "vssadmin.exe", "CMD executing volume shadow copy deletion"),
    ("explorer.exe", "mimikatz.exe", "Interactive user executing Mimikatz"),
]


@dataclass
class ProcessNode:
    """Represents a process execution node in the lineage tree."""
    pid: str
    ppid: str
    process_name: str
    command_line: str
    user: str
    timestamp_utc: str
    event_id: str
    parent_name: Optional[str] = None
    children: List["ProcessNode"] = field(default_factory=list)
    threat_alerts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "user": self.user,
            "timestamp_utc": self.timestamp_utc,
            "event_id": self.event_id,
            "parent_name": self.parent_name,
            "threat_alerts": self.threat_alerts,
            "children": [c.to_dict() for c in self.children],
        }


class ProcessLineageReconstructor:
    """Reconstructs process execution trees from timeline events."""

    def __init__(self, events: List[Event]):
        self.events = events

    def build_trees(self) -> List[ProcessNode]:
        """Parse process execution events and assemble into tree hierarchies."""
        nodes: Dict[str, ProcessNode] = {}
        ordered_keys: List[str] = []

        # 1. Extract process execution events
        for ev in self.events:
            raw = ev.raw or {}
            
            # Detect process execution events (EVTX 4688, bash executions, or generic PROCESS_START)
            is_proc = (
                ev.action in ("PROCESS_START", "EXEC")
                or raw.get("EventID") in (4688, 1)
                or "NewProcessName" in raw
                or "CommandLine" in raw
            )
            if not is_proc:
                continue

            # Extract PIDs and paths
            if "NewProcessId" in raw:
                pid = str(raw["NewProcessId"])
                ppid = str(raw.get("ProcessId") or raw.get("ParentProcessId") or "SYSTEM")
            else:
                pid = str(raw.get("ProcessId") or raw.get("pid") or f"PID-{len(nodes) + 1000}")
                ppid = str(raw.get("ParentProcessId") or raw.get("ppid") or "SYSTEM")
            
            proc_path = (
                raw.get("NewProcessName")
                or raw.get("CommandLine")
                or ev.object.path
                or "unknown.exe"
            )
            proc_name = proc_path.replace("\\", "/").split("/")[-1].split(" ")[0]
            cmd_line = raw.get("CommandLine") or ev.object.path or proc_name
            user = ev.user or raw.get("TargetUserName") or "UNKNOWN"

            node = ProcessNode(
                pid=pid,
                ppid=ppid,
                process_name=proc_name,
                command_line=cmd_line,
                user=user,
                timestamp_utc=ev.timestamp_utc,
                event_id=ev.event_id,
            )

            # Node key based on pid and timestamp
            key = f"{pid}_{ev.timestamp_utc}"
            nodes[key] = node
            ordered_keys.append(key)

        # 2. Check for suspicious parent-child spawns & link trees
        roots: List[ProcessNode] = []
        for key in ordered_keys:
            node = nodes[key]
            
            # Find parent if present among previous nodes
            parent_match = None
            for p_key in ordered_keys:
                candidate = nodes[p_key]
                if candidate.pid == node.ppid and candidate.timestamp_utc <= node.timestamp_utc:
                    parent_match = candidate
                    break

            if parent_match and parent_match is not node:
                node.parent_name = parent_match.process_name
                parent_match.children.append(node)
                
                # Check suspicious spawn rule
                for p_rule, c_rule, desc in SUSPICIOUS_SPAWNS:
                    if (
                        p_rule.lower() in parent_match.process_name.lower()
                        and c_rule.lower() in node.process_name.lower()
                    ):
                        alert_msg = f"SUSPICIOUS_SPAWN: {desc} ({parent_match.process_name} -> {node.process_name})"
                        node.threat_alerts.append(alert_msg)
            else:
                roots.append(node)

        return roots

    def render_ascii_tree(self, roots: Optional[List[ProcessNode]] = None) -> str:
        """Render a formatted ASCII process lineage tree for terminal output."""
        if roots is None:
            roots = self.build_trees()

        lines: List[str] = []

        def _walk(node: ProcessNode, prefix: str = "", is_last: bool = True):
            connector = "└── " if is_last else "├── "
            threat_marker = f" 🚨 [{'; '.join(node.threat_alerts)}]" if node.threat_alerts else ""
            lines.append(
                f"{prefix}{connector}{node.process_name} (PID: {node.pid}) [{node.user}] "
                f"`{node.command_line[:60]}`{threat_marker}"
            )
            child_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(node.children):
                _walk(child, child_prefix, i == len(node.children) - 1)

        for i, root in enumerate(roots):
            _walk(root, "", i == len(roots) - 1)

        return "\n".join(lines)
