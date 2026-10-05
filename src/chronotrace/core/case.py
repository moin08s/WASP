"""Case lifecycle, folder hierarchy, and state management."""

from __future__ import annotations
import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from chronotrace.core.config import CaseConfig
from chronotrace.core.writeguard import register_protected_path
from chronotrace.integrity.ledger import CustodyLedger
from chronotrace.acquire.manifest import CaseManifest
from chronotrace.acquire.hasher import Hasher


class Case:
    """Manages forensic case workspace, paths, integrity, and lifecycle."""

    def __init__(self, root_dir: str | Path):
        self.root = Path(root_dir).resolve()
        self.case_json_path = self.root / "case.json"
        self.config_path = self.root / "config.effective.toml"
        self.manifest_path = self.root / "manifest.json"
        self.evidence_dir = self.root / "evidence"
        self.custody_dir = self.root / "custody"
        self.ledger_path = self.custody_dir / "ledger.jsonl"
        self.index_dir = self.root / "index"
        self.derived_dir = self.root / "derived"
        self.reports_dir = self.root / "reports"

        self.metadata: Dict[str, Any] = {}
        self.config = CaseConfig()
        self.ledger: Optional[CustodyLedger] = None
        self.manifest: Optional[CaseManifest] = None

        if self.case_json_path.exists():
            self._load()

    @classmethod
    def create(
        cls,
        case_id: str,
        out_dir: str | Path,
        examiner: str = "Forensic Analyst",
        organization: str = "DFIR Unit",
        authorization_ref: str = "AUTH-001",
        description: str = "Digital Forensics Examination",
    ) -> "Case":
        """Initialize a new forensic case directory and create initial chain-of-custody entry."""
        root = Path(out_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)

        for d in ["evidence", "custody", "index", "derived", "reports"]:
            (root / d).mkdir(parents=True, exist_ok=True)

        instance = cls(root)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        instance.metadata = {
            "case_id": case_id,
            "created_utc": now_utc,
            "examiner": examiner,
            "organization": organization,
            "authorization_ref": authorization_ref,
            "description": description,
            "schema_version": "2.0.0",
            "tool_version": "1.3.0",
        }
        with open(instance.case_json_path, "w", encoding="utf-8") as f:
            json.dump(instance.metadata, f, indent=2, sort_keys=True)

        # Initialize configuration
        instance.config = CaseConfig.load()
        instance.config.general.case_id = case_id
        instance.config.general.examiner = examiner
        instance.config.general.organization = organization
        instance.config.general.authorization_ref = authorization_ref
        instance.config.general.description = description
        instance.config.save(instance.config_path)

        # Initialize custody ledger
        instance.ledger = CustodyLedger(instance.ledger_path)
        instance.ledger.append_event(
            event_type="case_created",
            actor=examiner,
            payload={
                "case_id": case_id,
                "organization": organization,
                "authorization_ref": authorization_ref,
            },
            timestamp_utc=now_utc,
        )

        # Initialize manifest
        instance.manifest = CaseManifest(instance.manifest_path, case_id=case_id)
        config_hash = Hasher.sha256_file(instance.config_path)
        instance.manifest.set_config("config.effective.toml", config_hash)
        instance.manifest.save()

        # Protect evidence directory against write operations
        register_protected_path(instance.evidence_dir)

        return instance

    @classmethod
    def open(cls, case_dir: str | Path) -> "Case":
        """Open an existing case directory."""
        root = Path(case_dir).resolve()
        if not (root / "case.json").exists():
            raise FileNotFoundError(f"Not a valid ChronoTrace case: {case_dir} (missing case.json)")
        instance = cls(root)
        return instance

    def _load(self) -> None:
        """Load metadata, ledger, and manifest for an existing case."""
        with open(self.case_json_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        if self.config_path.exists():
            self.config = CaseConfig.load(self.config_path)
        else:
            self.config = CaseConfig.load()

        self.ledger = CustodyLedger(self.ledger_path)
        self.manifest = CaseManifest(self.manifest_path, case_id=self.case_id)
        register_protected_path(self.evidence_dir)

    @property
    def case_id(self) -> str:
        return self.metadata.get("case_id", "CASE-UNKNOWN")

    @property
    def examiner(self) -> str:
        return self.metadata.get("examiner", "Forensic Examiner")

    @property
    def organization(self) -> str:
        return self.metadata.get("organization", "DFIR Unit")

    # High-level pipeline interfaces
    def acquire(self, source: str | Path, **kwargs) -> Dict[str, Any]:
        """Acquire evidence file or directory."""
        from chronotrace.acquire.imager import Imager
        imager = Imager(self)
        src_path = Path(source)
        if src_path.is_dir():
            return imager.acquire_directory_as_archive(src_path, **kwargs)
        return imager.acquire_file(src_path, **kwargs)

    def extract(self, plugins: Optional[List[str]] = None, profile: str = "all", jobs: int = 1):
        """Extract artefacts and metadata from evidence."""
        # Ensure plugins are registered
        import chronotrace.artifacts  # noqa: F401
        from chronotrace.extract.engine import ExtractionEngine
        engine = ExtractionEngine(self)
        return engine.run(plugin_names=plugins, profile=profile, jobs=jobs)

    def build_timeline(
        self,
        events: Optional[List[Any]] = None,
        deduplicate: bool = True,
        corroborate: bool = True,
        scan_threats: bool = True,
    ) -> List[Any]:
        """Reconstruct chronological activity timeline, run cross-source corroboration, and scan threats."""
        from chronotrace.timeline.builder import TimelineBuilder
        builder = TimelineBuilder(self.index_dir, derived_dir=self.derived_dir)
        collected_events = []
        if events is not None:
            collected_events.extend(events)
        else:
            # Load from derived/*.jsonl
            import json
            from chronotrace.core.models import Event
            for jsonl_file in self.derived_dir.glob("*.jsonl"):
                if jsonl_file.name == "timeline.jsonl":
                    continue
                with open(jsonl_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            collected_events.append(Event.model_validate_json(line))

        # 1. Cross-Source Corroboration Engine
        if corroborate and collected_events:
            from chronotrace.analysis.corroborator import CorroborationEngine
            c_engine = CorroborationEngine()
            c_result = c_engine.analyze(collected_events)
            # Save corroboration report
            c_report_path = self.derived_dir / "corroboration.json"
            with open(c_report_path, "w", encoding="utf-8") as f:
                json.dump(c_result.to_dict(), f, indent=2)
            if self.manifest:
                self.manifest.add_derived_file(
                    "derived/corroboration.json",
                    c_report_path.stat().st_size,
                    Hasher.sha256_file(c_report_path),
                )
            if self.ledger:
                self.ledger.append_event(
                    event_type="cross_source_corroborated",
                    actor=self.examiner,
                    payload=c_result.summary,
                )

        # 2. Threat & YARA Rule Scanning
        if scan_threats and collected_events:
            from chronotrace.analysis.rules import RuleEngine
            r_engine = RuleEngine()
            findings = r_engine.scan_events(collected_events)
            # Save threat alerts
            alerts_path = self.derived_dir / "threat_alerts.json"
            with open(alerts_path, "w", encoding="utf-8") as f:
                json.dump([f.to_dict() for f in findings], f, indent=2)
            if self.manifest:
                self.manifest.add_derived_file(
                    "derived/threat_alerts.json",
                    alerts_path.stat().st_size,
                    Hasher.sha256_file(alerts_path),
                )
            if self.ledger:
                self.ledger.append_event(
                    event_type="threat_rules_scanned",
                    actor=self.examiner,
                    payload={"total_findings": len(findings)},
                )

        builder.add_events(collected_events)
        sorted_events = builder.build(deduplicate=deduplicate)

        # Update manifest with index files
        if self.manifest:
            p_file = self.index_dir / "events.parquet"
            s_file = self.index_dir / "events.sqlite"
            if p_file.exists():
                self.manifest.add_index_file("index/events.parquet", p_file.stat().st_size, Hasher.sha256_file(p_file))
            if s_file.exists():
                self.manifest.add_index_file("index/events.sqlite", s_file.stat().st_size, Hasher.sha256_file(s_file))
            self.manifest.save()

        # Log to ledger
        if self.ledger:
            self.ledger.append_event(
                event_type="timeline_built",
                actor=self.examiner,
                payload={"total_events": len(sorted_events)},
            )

        return sorted_events

    def corroborate(self, time_window_seconds: int = 120):
        """Standalone cross-source corroboration and conflict analysis."""
        import json
        from chronotrace.core.models import Event
        from chronotrace.analysis.corroborator import CorroborationEngine

        events: List[Event] = []
        timeline_jsonl = self.derived_dir / "timeline.jsonl"
        if timeline_jsonl.exists():
            with open(timeline_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(Event.model_validate_json(line))
        else:
            for jsonl_file in self.derived_dir.glob("*.jsonl"):
                if jsonl_file.name == "timeline.jsonl":
                    continue
                with open(jsonl_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            events.append(Event.model_validate_json(line))

        engine = CorroborationEngine(time_window_seconds=time_window_seconds)
        result = engine.analyze(events)

        c_report_path = self.derived_dir / "corroboration.json"
        with open(c_report_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

        if self.manifest:
            self.manifest.add_derived_file(
                "derived/corroboration.json",
                c_report_path.stat().st_size,
                Hasher.sha256_file(c_report_path),
            )
            self.manifest.save()

        if self.ledger:
            self.ledger.append_event(
                event_type="cross_source_corroborated",
                actor=self.examiner,
                payload=result.summary,
            )

        # Rebuild timeline store with enriched corroboration
        from chronotrace.timeline.store import TimelineStore
        store = TimelineStore(self.index_dir)
        store.write_timeline(events)

        return result

    def scan_threats(self, custom_yara_path: Optional[str | Path] = None):
        """Standalone threat pattern & YARA rule evaluation across case evidence & timeline."""
        import json
        from chronotrace.core.models import Event
        from chronotrace.analysis.rules import RuleEngine, AlertFinding

        engine = RuleEngine(custom_yara_path=custom_yara_path)
        all_findings: List[AlertFinding] = []

        # Scan timeline events
        timeline_jsonl = self.derived_dir / "timeline.jsonl"
        events: List[Event] = []
        if timeline_jsonl.exists():
            with open(timeline_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(Event.model_validate_json(line))
            event_findings = engine.scan_events(events)
            all_findings.extend(event_findings)

        # Scan evidence files directly
        for ev_entry in self.manifest.evidence_entries:
            ev_file = self.root / ev_entry.path
            if ev_file.is_file():
                file_findings = engine.scan_file(ev_file)
                all_findings.extend(file_findings)

        alerts_path = self.derived_dir / "threat_alerts.json"
        with open(alerts_path, "w", encoding="utf-8") as f:
            json.dump([f.to_dict() for f in all_findings], f, indent=2)

        if self.manifest:
            self.manifest.add_derived_file(
                "derived/threat_alerts.json",
                alerts_path.stat().st_size,
                Hasher.sha256_file(alerts_path),
            )
            self.manifest.save()

        if self.ledger:
            self.ledger.append_event(
                event_type="threat_rules_scanned",
                actor=self.examiner,
                payload={"total_findings": len(all_findings)},
            )

        if events:
            from chronotrace.timeline.store import TimelineStore
            store = TimelineStore(self.index_dir)
            store.write_timeline(events)

        return all_findings

    def verify(self, rehash_evidence: bool = True, ledger_only: bool = False) -> Dict[str, Any]:
        """Perform comprehensive integrity verification."""
        from chronotrace.integrity.verifier import IntegrityVerifier
        verifier = IntegrityVerifier(self)
        result = verifier.verify(rehash_evidence=rehash_evidence, ledger_only=ledger_only)

        if self.ledger:
            self.ledger.append_event(
                event_type="integrity_verified",
                actor=self.examiner,
                payload={"status": result["overall_status"], "checked": result["checked_items"]},
            )
        return result

    def report(self, template: str = "full", formats: tuple[str, ...] = ("html", "json", "csv", "md"), redact: tuple[str, ...] = ()):
        """Generate structured investigation reports."""
        from chronotrace.report.builder import ReportBuilder
        builder = ReportBuilder(self).template(template).formats(*formats)
        if redact:
            builder.redact(*redact)
        return builder.build()

    def build_lineage(self):
        """Reconstruct parent-child process execution trees from timeline events."""
        from chronotrace.core.models import Event
        from chronotrace.analysis.lineage import ProcessLineageReconstructor

        timeline_jsonl = self.derived_dir / "timeline.jsonl"
        events: List[Event] = []
        if timeline_jsonl.exists():
            with open(timeline_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(Event.model_validate_json(line))

        reconstructor = ProcessLineageReconstructor(events)
        roots = reconstructor.build_trees()

        out_path = self.derived_dir / "process_lineage.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in roots], f, indent=2)

        if self.manifest:
            self.manifest.add_derived_file(
                "derived/process_lineage.json",
                out_path.stat().st_size,
                Hasher.sha256_file(out_path),
            )
            self.manifest.save()

        if self.ledger:
            self.ledger.append_event(
                event_type="process_lineage_reconstructed",
                actor=self.examiner,
                payload={"root_processes": len(roots)},
            )

        return roots

    def detect_anomalies(self, window_minutes: int = 15, z_threshold: float = 2.0):
        """Detect statistical burst anomalies, off-hours logins, and ransomware patterns."""
        from chronotrace.core.models import Event
        from chronotrace.analysis.anomalies import AnomalyDetector

        timeline_jsonl = self.derived_dir / "timeline.jsonl"
        events: List[Event] = []
        if timeline_jsonl.exists():
            with open(timeline_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(Event.model_validate_json(line))

        detector = AnomalyDetector(events, window_minutes=window_minutes, z_threshold=z_threshold)
        findings = detector.detect_all()

        out_path = self.derived_dir / "anomalies.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([f.to_dict() for f in findings], f, indent=2)

        if self.manifest:
            self.manifest.add_derived_file(
                "derived/anomalies.json",
                out_path.stat().st_size,
                Hasher.sha256_file(out_path),
            )
            self.manifest.save()

        if self.ledger:
            self.ledger.append_event(
                event_type="anomalies_detected",
                actor=self.examiner,
                payload={"total_anomalies": len(findings)},
            )

        return findings

    def scan_sigma(self, custom_rule_dirs: Optional[List[Path]] = None):
        """Scan timeline events using the native Sigma rule engine."""
        from chronotrace.core.models import Event
        from chronotrace.analysis.sigma import SigmaRuleEngine

        timeline_jsonl = self.derived_dir / "timeline.jsonl"
        events: List[Event] = []
        if timeline_jsonl.exists():
            with open(timeline_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(Event.model_validate_json(line))

        engine = SigmaRuleEngine(custom_rule_dirs=custom_rule_dirs)
        matches = engine.scan_events(events)

        out_path = self.derived_dir / "sigma_alerts.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([m.to_dict() for m in matches], f, indent=2)

        if self.manifest:
            self.manifest.add_derived_file(
                "derived/sigma_alerts.json",
                out_path.stat().st_size,
                Hasher.sha256_file(out_path),
            )
            self.manifest.save()

        if self.ledger:
            self.ledger.append_event(
                event_type="sigma_rules_evaluated",
                actor=self.examiner,
                payload={"total_matches": len(matches)},
            )

        return matches

    def export_bundle(self, output_file: Optional[Path] = None, passphrase: Optional[str] = None) -> Path:
        """Export case into an immutable, deterministically signed .wasp container."""
        from chronotrace.core.bundle import CaseBundleManager

        bundle_path = CaseBundleManager.export_bundle(self.root, output_file=output_file, passphrase=passphrase)

        if self.ledger:
            self.ledger.append_event(
                event_type="bundle_exported",
                actor=self.examiner,
                payload={"bundle_path": str(bundle_path), "bundle_hash": Hasher.sha256_file(bundle_path)},
            )

        return bundle_path

