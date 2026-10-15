"""
detector.py - Core log parsing and detection logic.

This module contains NO web code. Keeping the detection logic separate from
Flask makes it easy to test, easy to read, and easy to explain in an interview:

    raw text -> parse_log() -> analyze_log() -> dictionary of results

Expected log line format (one event per line, fields separated by "|"):

    2026-10-15 09:01:00 | 198.51.100.23 | admin | FAILED

Important limitation (also shown in the dashboard):
    Failures are counted across the WHOLE uploaded file. This version does not
    use a rolling time window (for example "5 failures within 10 minutes").
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime

# --------------------------------------------------------------------------
# Settings you can customise
# --------------------------------------------------------------------------
DEFAULT_THRESHOLD = 5          # alert when an IP has this many FAILED events or more
MIN_THRESHOLD = 1
MAX_THRESHOLD = 100_000
MAX_LINE_LENGTH = 500          # longer lines are reported as malformed, not parsed
MAX_MALFORMED_SHOWN = 50       # how many malformed entries the dashboard lists
TOP_IP_LIMIT = 10              # how many IPs appear in the "top failing" views
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
VALID_STATUSES = ("SUCCESS", "FAILED")
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9._@-]{1,64}")

SCOPE_NOTE = (
    "Counts cover the entire uploaded file. This version does not use a "
    "rolling time window, so failures that are spread over days are counted "
    "together. An alert is a signal that needs investigation, not proof of an attack."
)


# --------------------------------------------------------------------------
# Errors (all inherit from ValueError so callers can catch one type)
# --------------------------------------------------------------------------
class LogAnalysisError(ValueError):
    """The whole input could not be analysed. The message is safe to show users."""


class InvalidThresholdError(LogAnalysisError):
    """The threshold was not a whole number in the allowed range."""


class EmptyLogError(LogAnalysisError):
    """The input contained no log lines."""


class UnreadableLogError(LogAnalysisError):
    """The input was not readable UTF-8 text (for example a binary file)."""


class LogLineError(ValueError):
    """A single line could not be parsed. Becomes a 'malformed entry'."""


# --------------------------------------------------------------------------
# Data containers
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    ip: str
    username: str
    status: str  # "SUCCESS" or "FAILED"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.strftime(TIMESTAMP_FORMAT),
            "ip": self.ip,
            "username": self.username,
            "status": self.status,
        }


@dataclass(frozen=True)
class MalformedEntry:
    line_number: int
    reason: str
    raw: str  # shortened copy of the line; always escaped by the template


@dataclass(frozen=True)
class ParseResult:
    events: list
    malformed: list
    lines_read: int  # non-blank, non-comment lines


# --------------------------------------------------------------------------
# Validation and parsing
# --------------------------------------------------------------------------
def validate_threshold(value) -> int:
    """Return the threshold as an int, or raise InvalidThresholdError."""
    message = (
        f"Threshold must be a whole number from {MIN_THRESHOLD} to {MAX_THRESHOLD:,}."
    )
    if isinstance(value, bool):  # True/False are ints in Python; reject them
        raise InvalidThresholdError(message)
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if not re.fullmatch(r"[0-9]+", text):  # rejects "", "-1", "2.5", "abc"
            raise InvalidThresholdError(message)
        number = int(text)
    else:
        raise InvalidThresholdError(message)
    if not MIN_THRESHOLD <= number <= MAX_THRESHOLD:
        raise InvalidThresholdError(message)
    return number


def decode_log_bytes(data: bytes) -> str:
    """Turn uploaded bytes into text, rejecting empty or binary content."""
    if not data or not data.strip():
        raise EmptyLogError("The log file is empty. Upload a file that contains log lines.")
    if b"\x00" in data:  # NUL bytes mean this is not a text log
        raise UnreadableLogError("This does not look like a text log file. Upload a plain-text .log or .txt file.")
    try:
        return data.decode("utf-8-sig")  # utf-8-sig also strips a Windows BOM
    except UnicodeDecodeError:
        raise UnreadableLogError("The file is not valid UTF-8 text. Save it as UTF-8 and try again.") from None


def parse_line(line: str) -> LogEvent:
    """Parse one log line or raise LogLineError explaining what is wrong."""
    if len(line) > MAX_LINE_LENGTH:
        raise LogLineError(f"line is longer than {MAX_LINE_LENGTH} characters")

    parts = [part.strip() for part in line.split("|")]
    if len(parts) != 4:
        raise LogLineError(f"expected 4 fields separated by '|', found {len(parts)}")
    timestamp_text, ip_text, username, status = parts

    try:
        timestamp = datetime.strptime(timestamp_text, TIMESTAMP_FORMAT)
    except ValueError:
        raise LogLineError("invalid timestamp (expected YYYY-MM-DD HH:MM:SS)") from None

    try:
        ip = str(ipaddress.ip_address(ip_text))  # also normalises the text
    except ValueError:
        raise LogLineError("invalid IP address") from None

    if not USERNAME_PATTERN.fullmatch(username):
        raise LogLineError("invalid username (1-64 letters, digits, . _ @ -)")

    status = status.upper()
    if status not in VALID_STATUSES:
        raise LogLineError("unknown status (expected SUCCESS or FAILED)")

    return LogEvent(timestamp, ip, username, status)


def parse_log(text: str) -> ParseResult:
    """Parse every line. Bad lines are collected, never fatal."""
    events, malformed = [], []
    lines_read = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):  # skip blanks and comments
            continue
        lines_read += 1
        try:
            events.append(parse_line(line))
        except LogLineError as error:
            malformed.append(MalformedEntry(number, str(error), line[:120]))
    return ParseResult(events, malformed, lines_read)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
def analyze_log(text: str, threshold=DEFAULT_THRESHOLD) -> dict:
    """
    Run the full workflow and return a plain dictionary (easy to test and to
    convert to JSON). Steps: validate threshold -> parse -> count FAILED per IP
    -> compare with threshold -> build alerts.
    """
    threshold = validate_threshold(threshold)
    parsed = parse_log(text)
    if parsed.lines_read == 0:
        raise EmptyLogError("The log file has no log lines (only blank lines or comments).")

    failed_by_ip = Counter()
    success_by_ip = Counter()
    users_by_ip = defaultdict(set)
    failed_times = defaultdict(list)

    for event in parsed.events:
        if event.status == "FAILED":
            failed_by_ip[event.ip] += 1
            users_by_ip[event.ip].add(event.username)
            failed_times[event.ip].append(event.timestamp)
        else:  # SUCCESS is counted separately and never as a failure
            success_by_ip[event.ip] += 1

    per_ip = []
    for ip in set(failed_by_ip) | set(success_by_ip):
        times = failed_times[ip]
        per_ip.append({
            "ip": ip,
            "failed": failed_by_ip[ip],
            "success": success_by_ip[ip],
            "alert": failed_by_ip[ip] >= threshold,  # exact threshold counts
            "first_failed": min(times).strftime(TIMESTAMP_FORMAT) if times else "",
            "last_failed": max(times).strftime(TIMESTAMP_FORMAT) if times else "",
            "usernames": sorted(users_by_ip[ip]),
        })
    per_ip.sort(key=lambda row: (-row["failed"], row["ip"]))

    events_newest_first = sorted(parsed.events, key=lambda e: e.timestamp, reverse=True)
    failed_total = sum(failed_by_ip.values())

    return {
        "threshold": threshold,
        "total_events": len(parsed.events),
        "failed_total": failed_total,
        "success_total": len(parsed.events) - failed_total,
        "unique_ips": len(per_ip),
        "per_ip": per_ip,
        "alerts": [row for row in per_ip if row["alert"]],
        "top_ips": [row for row in per_ip if row["failed"] > 0][:TOP_IP_LIMIT],
        "events": [event.to_dict() for event in events_newest_first],
        "malformed_count": len(parsed.malformed),
        "malformed": [
            {"line": m.line_number, "reason": m.reason, "raw": m.raw}
            for m in parsed.malformed[:MAX_MALFORMED_SHOWN]
        ],
        "scope_note": SCOPE_NOTE,
    }


# --------------------------------------------------------------------------
# CSV export
# --------------------------------------------------------------------------
def _csv_safe(value) -> str:
    """
    Stop 'CSV injection': a cell starting with = + - @ can be run as a formula
    when the file is opened in Excel. A leading apostrophe keeps it as text.
    """
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _to_csv(header: list, rows: list) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([_csv_safe(cell) for cell in row])
    return buffer.getvalue()


def report_to_csv(analysis: dict) -> str:
    """One row per source IP, including whether it reached the threshold."""
    header = ["ip", "failed_attempts", "successful_attempts", "needs_investigation",
              "first_failed", "last_failed", "usernames_targeted"]
    rows = [
        [r["ip"], r["failed"], r["success"], "YES" if r["alert"] else "NO",
         r["first_failed"], r["last_failed"], "; ".join(r["usernames"])]
        for r in analysis["per_ip"]
    ]
    return _to_csv(header, rows)


def events_to_csv(analysis: dict) -> str:
    """Every parsed event, newest first."""
    header = ["timestamp", "ip", "username", "status"]
    rows = [[e["timestamp"], e["ip"], e["username"], e["status"]] for e in analysis["events"]]
    return _to_csv(header, rows)
