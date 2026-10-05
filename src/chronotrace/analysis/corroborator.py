"""Cross-Source Corroboration Engine for ChronoTrace.

Correlates events across disparate forensic artefacts (e.g., Prefetch, EVTX,
NTFS MFT, LNK, Browser History, and Registry) to verify activity, boost
event confidence, and flag anti-forensic anomalies (timestomping, out-of-order execution).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from chronotrace.core.models import Event


def _parse_dt(ts_str: str) -> Optional[datetime]:
    """Parse ISO8601 UTC timestamp string to datetime object."""
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


@dataclass
class CorroborationCluster:
    """Group of events from different artefacts corroborating a common activity."""
    entity: str
    plugins: List[str]
    event_ids: List[str]
    earliest_time: str
    latest_time: str
    time_delta_seconds: float
    description: str


@dataclass
class ConflictRecord:
    """Detected temporal conflict or anti-forensic anomaly between sources."""
    entity: str
    conflict_type: str
    description: str
    event_ids: List[str]
    severity: str  # HIGH, MEDIUM, LOW
    evidence_ids: List[str]


@dataclass
class CorroborationResult:
    """Results of cross-source corroboration analysis."""
    total_events: int = 0
    corroborated_count: int = 0
    conflict_count: int = 0
    clusters: List[Dict[str, Any]] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_events": self.total_events,
            "corroborated_count": self.corroborated_count,
            "conflict_count": self.conflict_count,
            "clusters": self.clusters,
            "conflicts": self.conflicts,
            "summary": self.summary,
        }


class CorroborationEngine:
    """
    Analyzes reconstructed events to link multiple independent forensic sources
    and detect anti-forensic anomalies.
    """

    def __init__(self, time_window_seconds: int = 120):
        self.time_window_seconds = time_window_seconds

    @staticmethod
    def _extract_entity_key(event: Event) -> Optional[str]:
        """Extract a canonical subject key (normalized file basename or process name)."""
        raw_path = event.object.path_norm or event.object.path or ""
        if raw_path:
            # Normalize slashes and extract filename
            norm = raw_path.replace("\\", "/").rstrip("/")
            base = norm.split("/")[-1].lower()
            if base and len(base) > 2 and base not in {"unknown", "none"}:
                return base

        # Fallback to raw process/target details if available
        if "process_name" in event.raw:
            return str(event.raw["process_name"]).lower().replace("\\", "/").split("/")[-1]
        if "file_name" in event.raw:
            return str(event.raw["file_name"]).lower().replace("\\", "/").split("/")[-1]

        return None

    def analyze(self, events: List[Event]) -> CorroborationResult:
        """
        Run cross-source corroboration and conflict analysis over a list of events.
        Mutates events in-place by adding tags, corroborated_by references,
        and warnings, then returns a structured CorroborationResult.
        """
        result = CorroborationResult(total_events=len(events))
        if not events:
            return result

        # 1. Group events by canonical entity key
        entity_groups: Dict[str, List[Event]] = {}
        for ev in events:
            key = self._extract_entity_key(ev)
            if key:
                entity_groups.setdefault(key, []).append(ev)

        corroborated_event_ids: Set[str] = set()
        clusters_found: List[CorroborationCluster] = []
        conflicts_found: List[ConflictRecord] = []

        # 2. Analyze each group for cross-source corroboration
        for entity, group_events in entity_groups.items():
            # Sort group chronologically
            valid_events = []
            for ev in group_events:
                dt = _parse_dt(ev.timestamp_utc)
                if dt:
                    valid_events.append((dt, ev))
            valid_events.sort(key=lambda item: item[0])

            # Check pairwise or cluster cross-source matches within time window
            n = len(valid_events)
            for i in range(n):
                dt_i, ev_i = valid_events[i]
                for j in range(i + 1, n):
                    dt_j, ev_j = valid_events[j]
                    delta = (dt_j - dt_i).total_seconds()
                    if delta > self.time_window_seconds:
                        break  # Outside temporal window

                    # Must originate from different plugins or different evidence artefacts
                    if ev_i.source.plugin != ev_j.source.plugin:
                        # Corroborate events
                        ref_j = f"{ev_j.source.plugin}:{ev_j.event_id[:8]}"
                        ref_i = f"{ev_i.source.plugin}:{ev_i.event_id[:8]}"

                        if ref_j not in ev_i.corroborated_by:
                            ev_i.corroborated_by.append(ref_j)
                        if ref_i not in ev_j.corroborated_by:
                            ev_j.corroborated_by.append(ref_i)

                        for ev, other in [(ev_i, ev_j), (ev_j, ev_i)]:
                            if "CORROBORATED" not in ev.tags:
                                ev.tags.append("CORROBORATED")
                            tag_pair = f"CORROBORATED:{other.source.plugin.upper()}"
                            if tag_pair not in ev.tags:
                                ev.tags.append(tag_pair)
                            # Boost confidence score
                            ev.confidence = min(1.0, round(ev.confidence + 0.1, 2))

                        corroborated_event_ids.add(ev_i.event_id)
                        corroborated_event_ids.add(ev_j.event_id)

                        cluster = CorroborationCluster(
                            entity=entity,
                            plugins=sorted(list({ev_i.source.plugin, ev_j.source.plugin})),
                            event_ids=[ev_i.event_id, ev_j.event_id],
                            earliest_time=ev_i.timestamp_utc,
                            latest_time=ev_j.timestamp_utc,
                            time_delta_seconds=round(delta, 2),
                            description=f"Activity on '{entity}' corroborated by {ev_i.source.plugin} and {ev_j.source.plugin} (within {delta:.1f}s)",
                        )
                        clusters_found.append(cluster)

            # 3. Conflict / Anti-Forensics / Timestomp Detection
            # Compare creation vs execution vs modification timestamps
            creation_events = [item for item in valid_events if item[1].timestamp_type == "created" or "create" in item[1].action.lower()]
            exec_events = [item for item in valid_events if "exec" in item[1].action.lower() or item[1].source.plugin in ("prefetch", "evtx")]
            mod_events = [item for item in valid_events if item[1].timestamp_type == "modified"]

            # Anomaly A: Execution prior to recorded creation time (> 30s gap)
            for dt_exec, ev_exec in exec_events:
                for dt_create, ev_create in creation_events:
                    # If executed before creation by more than 30s
                    if (dt_create - dt_exec).total_seconds() > 30.0:
                        warn = f"Anti-forensic anomaly: Executed at {ev_exec.timestamp_utc} prior to recorded file creation at {ev_create.timestamp_utc}"
                        ev_exec.warnings.append(warn)
                        ev_create.warnings.append(warn)
                        for ev in (ev_exec, ev_create):
                            if "CONFLICT" not in ev.tags:
                                ev.tags.append("CONFLICT")
                            if "TIMESTOMP_SUSPECT" not in ev.tags:
                                ev.tags.append("TIMESTOMP_SUSPECT")

                        conflicts_found.append(ConflictRecord(
                            entity=entity,
                            conflict_type="EXECUTION_PRE_CREATION",
                            description=warn,
                            event_ids=[ev_exec.event_id, ev_create.event_id],
                            severity="HIGH",
                            evidence_ids=list({ev_exec.evidence.evidence_id, ev_create.evidence.evidence_id}),
                        ))

            # Anomaly B: Modified timestamp earlier than creation timestamp (> 60s gap)
            for dt_mod, ev_mod in mod_events:
                for dt_create, ev_create in creation_events:
                    if (dt_create - dt_mod).total_seconds() > 60.0:
                        warn = f"Timestomp suspect: Modified time {ev_mod.timestamp_utc} precedes creation time {ev_create.timestamp_utc}"
                        ev_mod.warnings.append(warn)
                        if "CONFLICT" not in ev_mod.tags:
                            ev_mod.tags.append("CONFLICT")
                        if "TIMESTOMP_SUSPECT" not in ev_mod.tags:
                            ev_mod.tags.append("TIMESTOMP_SUSPECT")

                        conflicts_found.append(ConflictRecord(
                            entity=entity,
                            conflict_type="MODIFIED_PRE_CREATION",
                            description=warn,
                            event_ids=[ev_mod.event_id, ev_create.event_id],
                            severity="MEDIUM",
                            evidence_ids=list({ev_mod.evidence.evidence_id, ev_create.evidence.evidence_id}),
                        ))

        # Compile results
        result.corroborated_count = len(corroborated_event_ids)
        result.conflict_count = len(conflicts_found)
        result.clusters = [c.__dict__ for c in clusters_found]
        result.conflicts = [c.__dict__ for c in conflicts_found]
        result.summary = {
            "total_entities_analyzed": len(entity_groups),
            "corroborated_events": result.corroborated_count,
            "corroborated_clusters": len(result.clusters),
            "conflicts_detected": result.conflict_count,
        }

        return result
