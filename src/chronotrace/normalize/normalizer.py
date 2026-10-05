"""Normalizer producing standardized Event instances."""

from __future__ import annotations
import datetime
from typing import Any, Dict, List, Optional
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource, EventTimezone
from chronotrace.normalize.vocabularies import VALID_ACTIONS, VALID_ACTION_CLASSES, VALID_TIMESTAMP_TYPES


def create_event(
    timestamp_utc: str | datetime.datetime,
    action: str,
    artifact: str,
    plugin: str,
    evidence_id: str,
    evidence_sha256: str,
    object_path: Optional[str] = None,
    object_type: str = "file",
    action_class: Optional[str] = None,
    timestamp_raw: Optional[str] = None,
    timestamp_type: str = "modified",
    host: str = "UNKNOWN",
    user: str = "UNKNOWN",
    confidence: float = 1.0,
    rationale: str = "",
    record_id: Optional[Any] = None,
    record_offset: Optional[int] = None,
    tags: Optional[List[str]] = None,
    raw_data: Optional[Dict[str, Any]] = None,
    warnings: Optional[List[str]] = None,
) -> Event:
    """Create a strictly validated and normalized Event conforming to Schema 2.0.0."""
    if isinstance(timestamp_utc, datetime.datetime):
        if timestamp_utc.tzinfo is None:
            timestamp_utc = timestamp_utc.replace(tzinfo=datetime.timezone.utc)
        else:
            timestamp_utc = timestamp_utc.astimezone(datetime.timezone.utc)
        ts_utc_str = timestamp_utc.isoformat()
    else:
        ts_utc_str = str(timestamp_utc)

    # Validate vocabularies with sensible fallbacks
    safe_action = action if action in VALID_ACTIONS else "FILE_ACCESS"
    if not action_class:
        if safe_action.startswith("FILE_"):
            action_class = "file"
        elif safe_action.startswith("PROCESS_") or safe_action in ("SERVICE_INSTALL", "SCHEDULED_TASK_CREATE"):
            action_class = "process"
        elif safe_action.startswith("AUTH_") or safe_action.startswith("USER_"):
            action_class = "auth"
        elif safe_action.startswith("NETWORK_") or safe_action in ("DNS_QUERY", "WEB_VISIT"):
            action_class = "network"
        elif safe_action.startswith("REGISTRY_") or safe_action == "CONFIG_CHANGE":
            action_class = "config"
        else:
            action_class = "system"

    safe_action_class = action_class if action_class in VALID_ACTION_CLASSES else "other"
    safe_ts_type = timestamp_type if timestamp_type in VALID_TIMESTAMP_TYPES else "modified"

    obj = EventObject(
        type=object_type,
        path=object_path,
        extension=object_path.rsplit(".", 1)[-1].lower() if object_path and "." in object_path else None,
    )

    src = EventSource(
        artifact=artifact,
        plugin=plugin,
        plugin_version="1.0.0",
        evidence_id=evidence_id,
        record_id=record_id,
        record_offset=record_offset,
    )

    ev = EventEvidence(
        evidence_id=evidence_id,
        sha256=evidence_sha256,
    )

    return Event(
        timestamp_utc=ts_utc_str,
        timestamp_raw=timestamp_raw or ts_utc_str,
        timestamp_type=safe_ts_type,
        action=safe_action,
        action_class=safe_action_class,
        host=host,
        user=user,
        object=obj,
        source=src,
        evidence=ev,
        confidence=confidence,
        rationale=rationale,
        tags=tags or [],
        raw=raw_data or {},
        warnings=warnings or [],
    )
