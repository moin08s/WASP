"""Structured logging module with PII scrubbing."""

from __future__ import annotations
import json
import logging
import re
import sys
from typing import Any

# PII regex patterns for scrubbing
_EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_WIN_USER_REGEX = re.compile(r"(?:Users[\\/])([a-zA-Z0-9._-]+)", re.IGNORECASE)


def scrub_pii(text: str) -> str:
    """Scrub sensitive PII from log output."""
    if not isinstance(text, str):
        return text
    text = _EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
    text = _IPV4_REGEX.sub("[REDACTED_IP]", text)
    text = _WIN_USER_REGEX.sub(r"Users\[REDACTED_USER]", text)
    return text


class ScrubbingFormatter(logging.Formatter):
    """Custom formatter that scrubs PII and supports JSON or text."""
    def __init__(self, json_format: bool = False, scrub: bool = True):
        super().__init__()
        self.json_format = json_format
        self.scrub = scrub

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if self.scrub:
            msg = scrub_pii(msg)
        if self.json_format:
            payload: dict[str, Any] = {
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "name": record.name,
                "message": msg,
            }
            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)
            return json.dumps(payload)
        return f"[{record.levelname}] {record.name}: {msg}"


def setup_logger(
    name: str = "chronotrace",
    level: str = "INFO",
    json_format: bool = False,
    scrub: bool = True,
    log_file: str | None = None,
) -> logging.Logger:
    """Configures the primary ChronoTrace structured logger."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ScrubbingFormatter(json_format=json_format, scrub=scrub))
    logger.addHandler(handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(ScrubbingFormatter(json_format=json_format, scrub=scrub))
        logger.addHandler(file_handler)

    return logger
