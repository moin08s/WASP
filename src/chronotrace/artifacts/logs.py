"""Linux and Unix system log parser (auth.log, syslog, bash history)."""

from __future__ import annotations
import datetime
import re
from typing import Iterator
from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import register_plugin
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceFile, EvidenceView
from chronotrace.normalize.normalizer import create_event
from chronotrace.normalize.timezone import unix_to_datetime

# Syslog standard timestamp regex: "Oct  5 14:22:01" or ISO "2024-03-11T14:22:01.123456+00:00"
SYSLOG_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


@register_plugin
class LogsPlugin(ArtifactPlugin):
    """Parses Linux/Unix text logs (auth.log, syslog, bash_history)."""

    name: str = "linux_logs"
    version: str = "1.2.0"
    capabilities: list[str] = ["timeline", "auth", "execution"]
    applies_to: list[str] = ["linux", "unix", "all"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            path_lower = ef.virtual_path.lower()
            if any(l in path_lower for l in ["auth.log", "secure", "syslog", "messages", "bash_history"]):
                yield from self._parse_log_file(ef)

    def _parse_log_file(self, ef: EvidenceFile) -> Iterator[Event]:
        is_bash = "bash_history" in ef.virtual_path.lower()

        try:
            with ef.open_read() as f:
                last_bash_time = None
                for line in f:
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    if not line_str:
                        continue

                    # Handle bash_history with timestamps "#1615456789"
                    if is_bash:
                        if line_str.startswith("#") and line_str[1:].isdigit():
                            ts_val = int(line_str[1:])
                            last_bash_time = unix_to_datetime(ts_val)
                            continue
                        elif last_bash_time:
                            yield create_event(
                                timestamp_utc=last_bash_time,
                                action="PROCESS_START",
                                action_class="process",
                                timestamp_type="executed",
                                artifact=f"Linux:bash_history:{ef.virtual_path}",
                                plugin=self.name,
                                evidence_id=ef.evidence_id,
                                evidence_sha256=ef.sha256,
                                object_path=line_str,
                                confidence=0.95,
                                rationale="Bash history command execution with Unix timestamp",
                                tags=["execution", "bash"],
                                raw_data={"command": line_str},
                            )
                            last_bash_time = None
                        continue

                    # Handle syslog/auth.log lines
                    # E.g. "Mar 11 02:14:07 hostname sshd[123]: Accepted password for alice"
                    match = re.match(r"^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$", line_str)
                    if match:
                        mon_str, day_str, h_str, m_str, s_str, host, service, msg = match.groups()
                        month = SYSLOG_MONTHS.get(mon_str)
                        if month:
                            # Assume current or evidence year (default to 2024 or local year)
                            year = 2024
                            dt = datetime.datetime(year, month, int(day_str), int(h_str), int(m_str), int(s_str), tzinfo=datetime.timezone.utc)

                            action = "AUTH_LOGIN" if "accepted" in msg.lower() else "FILE_ACCESS"
                            action_class = "auth" if "accepted" in msg.lower() or "failed" in msg.lower() else "system"
                            tags = ["auth"] if "auth" in service.lower() or "ssh" in service.lower() else []

                            yield create_event(
                                timestamp_utc=dt,
                                action=action,
                                action_class=action_class,
                                timestamp_type="logged",
                                artifact=f"Linux:{service}:{ef.virtual_path}",
                                plugin=self.name,
                                evidence_id=ef.evidence_id,
                                evidence_sha256=ef.sha256,
                                host=host,
                                object_path=service,
                                confidence=0.85,
                                rationale=f"Syslog entry for {service} (assumed year {year})",
                                tags=tags,
                                raw_data={"line": line_str, "message": msg},
                            )
        except Exception:
            pass
