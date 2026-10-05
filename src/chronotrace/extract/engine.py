"""Extraction engine orchestrating plugin execution across evidence sources."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Type
from chronotrace.core.case import Case
from chronotrace.core.models import Event
from chronotrace.acquire.hasher import Hasher
from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import list_plugins
from chronotrace.ingest.evidence_view import EvidenceView


class ExtractionEngine:
    """Dispatches read-only EvidenceView to plugins and records derived outputs."""

    def __init__(self, case: Case):
        self.case = case

    def run(
        self,
        plugin_names: Optional[List[str]] = None,
        profile: str = "all",
        jobs: int = 1,
    ) -> List[Event]:
        """
        Execute registered artefact plugins, store derived jsonl streams, and update manifest.
        Returns all collected events.
        """
        self.case.derived_dir.mkdir(parents=True, exist_ok=True)
        manifest_evidence = self.case.manifest.data.get("evidence", []) if self.case.manifest else []
        evidence_view = EvidenceView(self.case.root, manifest_evidence)

        all_plugins = list_plugins()
        selected_plugins: List[Type[ArtifactPlugin]] = []

        for p_cls in all_plugins:
            if plugin_names and p_cls.name not in plugin_names:
                continue
            if profile != "all" and profile not in p_cls.applies_to and "all" not in p_cls.applies_to:
                continue
            selected_plugins.append(p_cls)

        all_events: List[Event] = []
        plugin_summary: Dict[str, int] = {}

        for p_cls in selected_plugins:
            plugin_instance = p_cls()
            plugin_events: List[Event] = []

            try:
                for event in plugin_instance.parse(evidence_view):
                    plugin_events.append(event)
                    all_events.append(event)
            except Exception as e:
                # Log warning and proceed
                pass

            # Write derived output file for this plugin: derived/<plugin>.jsonl
            derived_filename = f"{plugin_instance.name}.jsonl"
            derived_path = self.case.derived_dir / derived_filename

            if plugin_events:
                with open(derived_path, "w", encoding="utf-8") as f:
                    for ev in plugin_events:
                        f.write(json.dumps(ev.to_canonical_dict(), sort_keys=True) + "\n")

                sha = Hasher.sha256_file(derived_path)
                size_bytes = derived_path.stat().st_size
                rel_path = f"derived/{derived_filename}"

                if self.case.manifest:
                    self.case.manifest.add_derived_file(
                        rel_path=rel_path,
                        size_bytes=size_bytes,
                        sha256=sha,
                        plugin=plugin_instance.name,
                        plugin_version=plugin_instance.version,
                    )
            plugin_summary[plugin_instance.name] = len(plugin_events)

        if self.case.manifest:
            self.case.manifest.save()

        if self.case.ledger:
            self.case.ledger.append_event(
                event_type="artefacts_extracted",
                actor=self.case.examiner,
                payload={
                    "total_events": len(all_events),
                    "plugins_executed": list(plugin_summary.keys()),
                    "events_per_plugin": plugin_summary,
                },
            )

        return all_events
