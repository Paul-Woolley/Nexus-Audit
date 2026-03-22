"""
engine/ingestion.py
=====================
Log file ingestion and normalisation.

Accepts .log and .txt files, parses them line by line, and returns
a list of LogEntry objects with metadata attached.

Each LogEntry preserves the original raw line alongside whatever
structured fields could be extracted. The rule engine works against
the raw_line for pattern matching and against extracted fields for
field_value conditions.

SUPPORTED FORMATS:
    - Syslog / auth.log  (Jan 15 14:32:01 host sshd[123]: ...)
    - Apache access.log  (127.0.0.1 - - [15/Jan/2024:...] "GET /...")
    - Generic text logs  (YYYY-MM-DD HH:MM:SS [LEVEL] message)
    - Plain text         (any unstructured text -- still usable for pattern_match)

USAGE:
    from engine.ingestion import LogIngester

    ingester = LogIngester()
    entries  = ingester.ingest("path/to/auth.log")
    for entry in entries:
        print(entry.raw_line, entry.source_ip)
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
# LOG ENTRY DATACLASS
# =============================================================================

@dataclass
class LogEntry:
    """
    A single normalised log line with extracted metadata.

    Attributes
    ----------
    line_number  : int    -- 1-based line number in the source file
    raw_line     : str    -- the original, unmodified log line
    source_file  : str    -- path to the file this line came from
    timestamp    : str    -- ISO 8601 timestamp extracted from the line, or ""
    hostname     : str    -- hostname field, or ""
    service      : str    -- service/daemon name (e.g. "sshd"), or ""
    source_ip    : str    -- source IP address found in the line, or ""
    username     : str    -- username mentioned in the line, or ""
    log_level    : str    -- log level (ERROR, WARNING, INFO, etc.), or ""
    extra_fields : dict   -- any additional key/value pairs extracted
    """
    line_number:  int
    raw_line:     str
    source_file:  str
    timestamp:    str  = ""
    hostname:     str  = ""
    service:      str  = ""
    source_ip:    str  = ""
    username:     str  = ""
    log_level:    str  = ""
    extra_fields: dict = field(default_factory=dict)


# =============================================================================
# LOG INGESTER
# =============================================================================

class LogIngester:
    """
    Reads one or more log files and returns a flat list of LogEntry objects.

    Each line becomes one LogEntry. Empty lines and comment lines (# ...)
    are skipped. All parsing is best-effort -- unrecognised formats still
    produce a LogEntry with just raw_line and source_file set.
    """

    # ── Syslog / auth.log ─────────────────────────────────────────────────────
    # Jan 15 14:32:01 metasploitable sshd[1234]: Failed password for root from 10.0.0.5 port 54321
    _SYSLOG = re.compile(
        r"^(\w{3}\s+\d+\s+[\d:]+)\s+"   # timestamp  (group 1)
        r"(\S+)\s+"                       # hostname   (group 2)
        r"(\S+?)(?:\[(\d+)\])?:\s*"       # service[pid] (groups 3, 4)
        r"(.*)"                            # message    (group 5)
    )

    # ── ISO 8601 generic ──────────────────────────────────────────────────────
    # 2024-01-15 14:32:01 [ERROR] message text
    # 2024-01-15T14:32:01 WARNING message text
    _ISO_LOG = re.compile(
        r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"  # timestamp (group 1)
        r"(?:\s*\[?(\w+)\]?)?"                            # level     (group 2)
        r"\s+(.*)"                                         # message   (group 3)
    )

    # ── Apache access.log ─────────────────────────────────────────────────────
    # 192.168.1.5 - frank [15/Jan/2024:14:32:01 +0000] "GET /admin HTTP/1.1" 404 512
    _APACHE = re.compile(
        r"^([\d.]+)\s+-\s+(\S+)\s+"    # IP, user (groups 1-2)
        r"\[([^\]]+)\]\s+"              # timestamp (group 3)
        r'"(\w+)\s+(\S+).*?"\s+'        # method, url (groups 4-5)
        r"(\d+)\s+(\d+)"                # status, bytes (groups 6-7)
    )

    # ── IP address anywhere in line ───────────────────────────────────────────
    _IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    # ── Username patterns ─────────────────────────────────────────────────────
    _USER_PATTERNS = [
        re.compile(r"(?:for|user)\s+(?:invalid user\s+)?(\S+)(?:\s+from|\s+port|$)", re.I),
        re.compile(r"user=(\S+)", re.I),
        re.compile(r"USER=(\S+)", re.I),
    ]

    # ─────────────────────────────────────────────────────────────────────────

    def ingest(self, path: str | Path) -> list[LogEntry]:
        """
        Read a single log file and return its entries.

        Parameters
        ----------
        path : str or Path
            Path to the log file. Must exist and be readable.

        Returns
        -------
        list[LogEntry]
            One entry per non-empty, non-comment line.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ValueError
            If the file extension is not supported.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        suffix = path.suffix.lower()
        if suffix not in {".log", ".txt", ".csv"}:
            raise ValueError(
                f"Unsupported file extension '{suffix}'. "
                f"Supported: .log  .txt  .csv"
            )

        entries = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line_number, raw_line in enumerate(f, start=1):
                    raw_line = raw_line.rstrip("\n\r")
                    # Skip blank lines and comment lines
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    entry = self._parse_line(raw_line, line_number, str(path))
                    entries.append(entry)
        except OSError as exc:
            raise OSError(f"Cannot read log file '{path}': {exc}") from exc

        return entries

    def ingest_directory(self, directory: str | Path) -> list[LogEntry]:
        """
        Ingest all supported log files from a directory (non-recursive).

        Returns all entries in file-name order. Each entry's source_file
        field identifies which file it came from.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        all_entries = []
        for f in sorted(directory.iterdir()):
            if f.suffix.lower() in {".log", ".txt"}:
                all_entries.extend(self.ingest(f))
        return all_entries

    def _parse_line(
        self,
        raw_line:    str,
        line_number: int,
        source_file: str,
    ) -> LogEntry:
        """
        Try each parser in order. Return a populated LogEntry.
        Falls back to a minimal entry if nothing matches.
        """
        entry = LogEntry(
            line_number=line_number,
            raw_line=raw_line,
            source_file=source_file,
        )

        # Try syslog first (most common for auth.log, syslog)
        m = self._SYSLOG.match(raw_line)  # Match syslog format
        if m:
            entry.timestamp = m.group(1)  # Extract timestamp
            entry.hostname  = m.group(2)  # Extract hostname
            entry.service   = m.group(3)  # Extract service name
            self._extract_ip_and_user(raw_line, entry)  # Extract IP and user
            return entry

        # Try ISO 8601 format
        m = self._ISO_LOG.match(raw_line)  # Match ISO log format
        if m:
            entry.timestamp = m.group(1)  # Extract timestamp
            entry.log_level = m.group(2) or ""  # Extract log level
            self._extract_ip_and_user(raw_line, entry)  # Extract IP and user
            return entry

        # Try Apache access log
        m = self._APACHE.match(raw_line)  # Match Apache format
        if m:
            entry.source_ip = m.group(1)  # Extract client IP
            entry.username  = m.group(2) if m.group(2) != "-" else ""  # Extract username
            entry.timestamp = m.group(3)  # Extract timestamp
            entry.service   = "apache"  # Set service to apache
            entry.extra_fields = {  # Store additional fields
                "http_method": m.group(4),  # HTTP method
                "url":         m.group(5),  # Requested URL
                "status_code": int(m.group(6)),  # HTTP status code
                "bytes":       int(m.group(7)),  # Response bytes
            }
            return entry

        # Fallback: still extract IP and user from unstructured line
        self._extract_ip_and_user(raw_line, entry)  # Best-effort extraction
        return entry

    def _extract_ip_and_user(self, raw_line: str, entry: LogEntry) -> None:
        """Best-effort extraction of IP and username from any log line."""
        ips = self._IP_PATTERN.findall(raw_line)
        if ips:
            # Prefer IPs that are NOT 127.0.0.1 or the localhost range
            non_local = [ip for ip in ips if not ip.startswith("127.")]
            entry.source_ip = non_local[0] if non_local else ips[0]

        for pattern in self._USER_PATTERNS:
            m = pattern.search(raw_line)
            if m:
                user = m.group(1).strip("'\"")
                # Filter out noise values
                if user and user not in ("for", "from", "by", "with", "to"):
                    entry.username = user
                    break
