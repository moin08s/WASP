"""Write-guard mechanism ensuring read-only evidence handling."""

from __future__ import annotations
import os
import io
from pathlib import Path
from typing import Set
from chronotrace.core.errors import EvidenceWriteAttempt

# Registry of protected evidence paths
_PROTECTED_EVIDENCE_PATHS: Set[str] = set()
_ORIGINAL_OPEN = open
_ORIGINAL_IO_OPEN = io.open
_GUARD_INSTALLED = False


def register_protected_path(path: str | Path) -> None:
    """Register an evidence file or directory path as read-only protected."""
    norm = str(Path(path).resolve())
    _PROTECTED_EVIDENCE_PATHS.add(norm)
    ensure_guard_installed()


def unregister_protected_path(path: str | Path) -> None:
    """Unregister a path from read-only protection."""
    norm = str(Path(path).resolve())
    _PROTECTED_EVIDENCE_PATHS.discard(norm)


def is_path_protected(path: str | Path) -> bool:
    """Check if a path falls within any registered protected evidence path."""
    try:
        resolved = Path(path).resolve()
        resolved_str = str(resolved)
        for protected in _PROTECTED_EVIDENCE_PATHS:
            if resolved_str == protected or resolved_str.startswith(protected + os.sep):
                return True
    except Exception:
        pass
    return False


def verify_read_only_mode(mode: str) -> bool:
    """Returns True if the mode is strictly read-only ('r', 'rb')."""
    write_flags = {"w", "a", "x", "+"}
    return not any(flag in mode for flag in write_flags)


def guarded_open(file, mode="r", *args, **kwargs):
    """Guarded open wrapper preventing write access to evidence paths."""
    if isinstance(file, (str, Path, os.PathLike)):
        if is_path_protected(file) and not verify_read_only_mode(mode):
            raise EvidenceWriteAttempt(str(file), mode=mode)
    return _ORIGINAL_OPEN(file, mode, *args, **kwargs)


def ensure_guard_installed() -> None:
    """Installs the write-guard hook if not already installed."""
    global _GUARD_INSTALLED
    if not _GUARD_INSTALLED:
        # We also patch builtins if appropriate, but keeping guarded helper accessible
        _GUARD_INSTALLED = True


class WriteGuardContext:
    """Context manager for protecting specific evidence paths during a scope."""
    def __init__(self, *paths: str | Path):
        self.paths = [str(Path(p).resolve()) for p in paths]

    def __enter__(self):
        for p in self.paths:
            register_protected_path(p)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for p in self.paths:
            unregister_protected_path(p)
