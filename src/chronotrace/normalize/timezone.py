"""Timestamp decoding, conversion, and timezone normalization."""

from __future__ import annotations
import datetime
from typing import Optional, Tuple

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
CHROME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime_to_datetime(filetime: int) -> Optional[datetime.datetime]:
    """Convert Windows 64-bit FILETIME (100-ns intervals since 1601-01-01) to UTC datetime."""
    if not filetime or filetime < 0:
        return None
    try:
        microseconds = filetime // 10
        return FILETIME_EPOCH + datetime.timedelta(microseconds=microseconds)
    except (OverflowError, OSError):
        return None


def chrome_time_to_datetime(chrome_time: int) -> Optional[datetime.datetime]:
    """Convert Chrome / WebKit microsecond timestamp (since 1601-01-01) to UTC datetime."""
    if not chrome_time or chrome_time < 0:
        return None
    try:
        return CHROME_EPOCH + datetime.timedelta(microseconds=chrome_time)
    except (OverflowError, OSError):
        return None


def unix_to_datetime(seconds: float | int) -> Optional[datetime.datetime]:
    """Convert Unix timestamp (seconds since 1970-01-01) to UTC datetime."""
    if not seconds or seconds < 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def parse_iso_timestamp(ts_str: str) -> Tuple[Optional[datetime.datetime], str]:
    """
    Parse an ISO / RFC 3339 string to UTC datetime.
    Returns: (utc_datetime, formatted_rfc3339)
    """
    if not ts_str:
        return None, ""
    try:
        # Handle trailing Z
        cleaned = ts_str.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        else:
            dt = dt.astimezone(datetime.timezone.utc)
        return dt, dt.isoformat()
    except Exception:
        return None, ts_str
