"""Core exception classes for ChronoTrace."""

class ChronoTraceError(Exception):
    """Base exception for all ChronoTrace errors."""
    pass


class EvidenceWriteAttempt(ChronoTraceError):
    """Raised when an attempt is made to open or write to an evidence path."""
    def __init__(self, path: str, mode: str = "write"):
        super().__init__(
            f"Forensic write-guard violation: Attempted '{mode}' operation on evidence path: {path}"
        )
        self.path = path
        self.mode = mode


class EvidenceCorruptError(ChronoTraceError):
    """Raised when evidence reading detects corruption or unreadable bad sectors."""
    def __init__(self, message: str, offset: int | None = None):
        detail = f" at offset {offset}" if offset is not None else ""
        super().__init__(f"Evidence corrupt{detail}: {message}")
        self.offset = offset


class IntegrityError(ChronoTraceError):
    """Raised when SHA-256 hash or chain-of-custody verification fails."""
    pass


class CaseLockedError(ChronoTraceError):
    """Raised when attempting to modify a case currently locked by another process."""
    pass


class PluginError(ChronoTraceError):
    """Raised when an artefact plugin fails during discovery or execution."""
    pass


class SchemaError(ChronoTraceError):
    """Raised when an event does not conform to the Unified Event Schema."""
    pass
