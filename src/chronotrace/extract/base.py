"""ArtifactPlugin base class defining plugin interface."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterator, List
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceView


class ArtifactPlugin(ABC):
    """Base class for all ChronoTrace forensic artefact parsers and extractors."""

    name: str = "base_plugin"
    version: str = "1.0.0"
    capabilities: List[str] = ["timeline", "metadata"]
    applies_to: List[str] = ["all"]
    parallel_safe: bool = True

    @abstractmethod
    def parse(self, source: EvidenceView) -> Iterator[Event]:
        """
        Parse targeted artefacts from the read-only EvidenceView and yield normalized Events.
        Must never modify evidence paths.
        """
        raise NotImplementedError
