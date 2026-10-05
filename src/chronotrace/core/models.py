"""Unified Event Schema 2.0.0 and Core Data Models."""

from __future__ import annotations
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# Namespace for UUIDv5 event ID generation
CHRONOTRACE_NAMESPACE = uuid.UUID("9f1c0a1e-6a1f-5a4f-9c2f-1b2c3d4e5f60")


class EventObject(BaseModel):
    """Target object of an observable event."""
    type: str = "file"
    path: Optional[str] = None
    path_norm: Optional[str] = None
    size: Optional[int] = None
    inode: Optional[int] = None
    extension: Optional[str] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class EventSource(BaseModel):
    """Provenance information tracking back to the source artefact record."""
    artifact: str
    plugin: str
    plugin_version: str = "1.0.0"
    evidence_id: str
    record_id: Optional[Any] = None
    record_offset: Optional[int] = None
    record_type: Optional[str] = None


class EventEvidence(BaseModel):
    """Evidence container and integrity binding."""
    evidence_id: str
    sha256: str
    container: Optional[str] = None


class EventTimezone(BaseModel):
    """Timezone resolution details."""
    source: str = "UTC"
    name: str = "UTC"
    offset: str = "+00:00"
    confidence: float = 1.0


class Event(BaseModel):
    """Unified Forensic Event Model conforming to Schema version 2.0.0."""
    event_id: str = ""
    schema_version: str = "2.0.0"

    timestamp_utc: str
    timestamp_raw: Optional[str] = None
    timestamp_type: str = "modified"
    timestamp_confidence: float = 1.0

    action: str = "FILE_ACCESS"
    action_class: str = "file"

    host: str = "UNKNOWN"
    user: str = "UNKNOWN"
    user_sid: Optional[str] = None

    object: EventObject = Field(default_factory=EventObject)
    source: EventSource
    evidence: EventEvidence

    confidence: float = 1.0
    rationale: str = ""

    tags: List[str] = Field(default_factory=list)
    corroborated_by: List[str] = Field(default_factory=list)
    tz: Optional[EventTimezone] = None

    raw: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)

    def compute_deterministic_id(self) -> str:
        """Derive deterministic UUIDv5 = uuid5(NAMESPACE, sha256(canonical_fields))."""
        canonical = {
            "timestamp_utc": self.timestamp_utc,
            "action": self.action,
            "host": self.host,
            "user": self.user,
            "object_path": self.object.path_norm or self.object.path,
            "artifact": self.source.artifact,
            "record_id": str(self.source.record_id),
            "record_offset": self.source.record_offset,
            "evidence_sha256": self.evidence.sha256,
        }
        canonical_str = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        return str(uuid.uuid5(CHRONOTRACE_NAMESPACE, digest))

    def model_post_init(self, __context: Any) -> None:
        """Ensure deterministic ID and normalized paths upon instantiation."""
        if self.object.path and not self.object.path_norm:
            self.object.path_norm = self.object.path.replace("\\", "/").lower()
        if not self.event_id:
            self.event_id = self.compute_deterministic_id()

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert model to canonical dictionary with sorted keys."""
        return json.loads(self.model_dump_json())
