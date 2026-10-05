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

    def build_timeline(self, events: Optional[List[Any]] = None, deduplicate: bool = True) -> List[Any]:
        """Reconstruct chronological activity timeline and write to index/ and derived/."""
        from chronotrace.timeline.builder import TimelineBuilder
        builder = TimelineBuilder(self.index_dir, derived_dir=self.derived_dir)
        if events is not None:
            builder.add_events(events)
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
                            builder.add_event(Event.model_validate_json(line))

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
