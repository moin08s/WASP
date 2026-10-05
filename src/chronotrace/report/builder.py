"""ReportBuilder compiling structured forensic investigation reports."""

from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import jinja2
from chronotrace.core.case import Case
from chronotrace.core.models import Event
from chronotrace.acquire.hasher import Hasher
from chronotrace.integrity.verifier import IntegrityVerifier
from chronotrace.report.redaction import RedactionEngine
from chronotrace.timeline.query import TimelineQuery


class ReportBuilder:
    """Renders normalized events, provenance, and integrity into structured reports."""

    def __init__(self, case: Case):
        self.case = case
        self.template_name = "full"
        self.formats_list: List[str] = ["html", "json", "csv", "md"]
        self.redact_categories: Set[str] = set()

    def template(self, name: str) -> "ReportBuilder":
        self.template_name = name
        return self

    def formats(self, *fmts: str) -> "ReportBuilder":
        self.formats_list = [f.lower().strip() for f in fmts]
        return self

    def redact(self, *categories: str) -> "ReportBuilder":
        for cat in categories:
            for item in cat.split(","):
                clean = item.strip().lower()
                if clean:
                    self.redact_categories.add(clean)
        return self

    def build(self) -> Dict[str, str]:
        """
        Generate configured structured investigation reports.
        Returns mapping of format to generated file path.
        """
        self.case.reports_dir.mkdir(parents=True, exist_ok=True)
        results: Dict[str, str] = {}

        # 1. Run Integrity Verification
        verifier = IntegrityVerifier(self.case)
        integrity_status = verifier.verify(rehash_evidence=False)

        # 2. Query Timeline Events
        tq = TimelineQuery(self.case.index_dir)
        raw_events_data = tq.filter_events(limit=50000)

        # Convert back to Event models for redaction
        events: List[Event] = []
        for r in raw_events_data:
            try:
                raw_dict = json.loads(r.get("raw_json", "{}")) if r.get("raw_json") else {}
                tags_list = [t.strip() for t in r.get("tags", "").split(",") if t.strip()]
                corrob_list = [c.strip() for c in r.get("corroborated_by", "").split(",") if c.strip()]
                warn_list = [w.strip() for w in r.get("warnings", "").split(";") if w.strip()]
                ev = Event(
                    event_id=r["event_id"],
                    timestamp_utc=r["timestamp_utc"],
                    timestamp_raw=r.get("timestamp_raw"),
                    timestamp_type=r.get("timestamp_type", "modified"),
                    action=r["action"],
                    action_class=r.get("action_class", "file"),
                    host=r.get("host", "UNKNOWN"),
                    user=r.get("user", "UNKNOWN"),
                    object={"type": "file", "path": r.get("object_path", "")},
                    source={
                        "artifact": r.get("artifact", ""),
                        "plugin": r.get("plugin", ""),
                        "evidence_id": r.get("evidence_id", ""),
                    },
                    evidence={
                        "evidence_id": r.get("evidence_id", ""),
                        "sha256": r.get("evidence_sha256", ""),
                    },
                    confidence=r.get("confidence", 1.0),
                    rationale=r.get("rationale", ""),
                    tags=tags_list,
                    corroborated_by=corrob_list,
                    warnings=warn_list,
                    raw=raw_dict,
                )
                events.append(ev)
            except Exception:
                pass

        # 3. Apply Redaction if requested
        if self.redact_categories:
            engine = RedactionEngine(self.redact_categories, self.case.reports_dir)
            events = [engine.redact_event(e) for e in events]
            engine.save_mapping()

        # 4. Context for Templates
        manifest_data = self.case.manifest.data if self.case.manifest else {}
        custody_entries = self.case.ledger.get_entries() if self.case.ledger else []

        # Load Corroboration & Threat Data if present
        corroboration_data = {}
        c_path = self.case.derived_dir / "corroboration.json"
        if c_path.exists():
            try:
                with open(c_path, "r", encoding="utf-8") as f:
                    corroboration_data = json.load(f)
            except Exception:
                pass

        threat_alerts_data = []
        t_path = self.case.derived_dir / "threat_alerts.json"
        if t_path.exists():
            try:
                with open(t_path, "r", encoding="utf-8") as f:
                    threat_alerts_data = json.load(f)
            except Exception:
                pass

        context = {
            "case": self.case,
            "manifest": manifest_data,
            "timeline_events": events,
            "integrity": integrity_status,
            "custody_entries": custody_entries,
            "corroboration": corroboration_data,
            "threat_alerts": threat_alerts_data,
        }

        # Setup Jinja2 Environment
        tmpl_dir = Path(__file__).parent / "templates"
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(tmpl_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )

        case_id = self.case.case_id

        # Render HTML
        if "html" in self.formats_list:
            html_tmpl = env.get_template("report.html.j2")
            rendered_html = html_tmpl.render(**context)
            html_path = self.case.reports_dir / f"{case_id}_full.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(rendered_html)
            self._register_report(html_path)
            results["html"] = str(html_path)

        # Render Markdown
        if "md" in self.formats_list or "markdown" in self.formats_list:
            md_tmpl = env.get_template("report.md.j2")
            rendered_md = md_tmpl.render(**context)
            md_path = self.case.reports_dir / f"{case_id}_summary.md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(rendered_md)
            self._register_report(md_path)
            results["md"] = str(md_path)

        # Render JSON
        if "json" in self.formats_list:
            json_path = self.case.reports_dir / f"{case_id}_full.json"
            json_payload = {
                "case_metadata": self.case.metadata,
                "integrity_attestation": integrity_status,
                "manifest": manifest_data,
                "custody_ledger": custody_entries,
                "corroboration": corroboration_data,
                "threat_alerts": threat_alerts_data,
                "events_count": len(events),
                "events": [e.to_canonical_dict() for e in events],
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(json_payload, f, indent=2, sort_keys=True)
            self._register_report(json_path)
            results["json"] = str(json_path)

        # Render CSV
        if "csv" in self.formats_list:
            csv_path = self.case.reports_dir / f"{case_id}_full.csv"
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp_utc",
                    "action",
                    "user",
                    "object_path",
                    "artifact",
                    "plugin",
                    "confidence",
                    "rationale",
                    "tags",
                    "event_id",
                ])
                for e in events:
                    writer.writerow([
                        e.timestamp_utc,
                        e.action,
                        e.user,
                        e.object.path or "",
                        e.source.artifact,
                        e.source.plugin,
                        e.confidence,
                        e.rationale,
                        ";".join(e.tags),
                        e.event_id,
                    ])
            self._register_report(csv_path)
            results["csv"] = str(csv_path)

        # Record report generation in custody ledger
        if self.case.ledger:
            self.case.ledger.append_event(
                event_type="report_generated",
                actor=self.case.examiner,
                payload={
                    "template": self.template_name,
                    "formats": self.formats_list,
                    "generated_files": list(results.keys()),
                },
            )

        return results

    def _register_report(self, path: Path) -> None:
        """Register report file into manifest and compute SHA-256."""
        sha = Hasher.sha256_file(path)
        rel = str(path.relative_to(self.case.root)).replace("\\", "/")
        if self.case.manifest:
            self.case.manifest.add_report_file(rel, sha)
            self.case.manifest.save()
