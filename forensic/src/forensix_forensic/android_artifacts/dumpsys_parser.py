"""Parser for Android dumpsys usagestats output obtained from physical/logical non-rooted ADB triage."""

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensix_forensic.evidence_io import (
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
)

from .documents import AndroidDocumentParserError, _safe_text

# Regex to match in-memory event lines from 'dumpsys usagestats'
# Example: time="2026-03-01 14:22:10" type=MOVE_TO_FOREGROUND package=com.whatsapp class=com.whatsapp.HomeActivity flags=0x0
# or:      time="2026-03-01 14:22:10" type=1 package=com.whatsapp
_EVENT_LINE_RE = re.compile(
    r'time="(?P<time>[^"]+)"\s+type=(?P<type>[A-Za-z0-9_]+)\s+package=(?P<package>[A-Za-z0-9_.]+)'
    r"(?:\s+class=(?P<class>[^\s]+))?"
    r"(?:\s+flags=(?P<flags>[^\s]+))?"
    r"(?:\s+standbyBucket=(?P<bucket>[^\s]+))?"
    r"(?:\s+reason=(?P<reason>[^\s]+))?"
    r"(?:\s+shortcutId=(?P<shortcut>[^\s]+))?"
)

# Numeric event type mapping according to Android UsageEvents
_NUMERIC_EVENT_TYPES: dict[str, str] = {
    "1": "MOVE_TO_FOREGROUND",
    "2": "MOVE_TO_BACKGROUND",
    "5": "CONFIGURATION_CHANGE",
    "7": "USER_INTERACTION",
    "8": "SHORTCUT_INVOCATION",
    "15": "STANDBY_BUCKET_CHANGED",
    "16": "FOREGROUND_SERVICE_START",
    "17": "FOREGROUND_SERVICE_STOP",
    "23": "ACTIVITY_STOPPED",
    "26": "ACTIVITY_RESUMED",
}

# Regex to find key="value" or key=value tokens on aggregate package lines
_KV_TOKEN_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')


def _parse_dumpsys_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    val = value.strip()
    # Try ISO format
    try:
        dt = datetime.fromisoformat(val.replace(" ", "T"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        pass

    # Try common formats
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue

    # Try epoch milliseconds / seconds
    try:
        num = float(val)
        if num > 1e11:  # Epoch milliseconds
            num /= 1000.0
        dt = datetime.fromtimestamp(num, tz=UTC)
        if 1990 <= dt.year <= 2200:
            return dt
    except (ValueError, OverflowError, OSError):
        pass

    return None


class AndroidDumpsysUsageStatsParser:
    """Bounded parser for non-rooted Android 'dumpsys usagestats' command output."""

    metadata = ParserMetadata(
        parser_id="android.dumpsys.usagestats",
        name="Android dumpsys usagestats output",
        version="1.0.0",
        artifact_categories=("application",),
        required_tables=frozenset(),
        access_level="logical",
        maturity="validated",
        source_path_hints=(
            "dumpsys_usagestats.txt",
            "usagestats.txt",
            "usagestats.log",
            "dumpsys.txt",
            "usagestats",
        ),
        description=(
            "Parses plaintext Android dumpsys usagestats outputs from non-rooted ADB triage, "
            "extracting application foreground switches, user interactions, and aggregate runtimes."
        ),
        input_formats=("text", "log"),
    )

    def can_parse(self, source_locator: str) -> bool:
        lowered = source_locator.casefold()
        return (
            lowered.endswith("dumpsys_usagestats.txt")
            or lowered.endswith("usagestats.txt")
            or lowered.endswith("usagestats.log")
            or lowered.endswith("dumpsys.txt")
            or ("dumpsys" in lowered and "usagestats" in lowered)
        )

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        content = _safe_text(path)
        lines = content.splitlines()

        artifacts: list[ParsedArtifact] = []
        is_usagestats_dump = False

        for line_no, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            if "usagestats" in line_str.casefold() or "in-memory event log" in line_str.casefold():
                is_usagestats_dump = True

            # 1. Parse Event Lines
            event_match = _EVENT_LINE_RE.search(line_str)
            if event_match:
                is_usagestats_dump = True
                raw_type = event_match.group("type")
                event_label = _NUMERIC_EVENT_TYPES.get(raw_type, raw_type).upper()
                package = event_match.group("package")
                event_time = _parse_dumpsys_timestamp(event_match.group("time"))
                activity_class = event_match.group("class")

                metadata: dict[str, Any] = {
                    "package": package,
                    "event_type": event_label,
                    "class": activity_class,
                    "flags": event_match.group("flags"),
                    "standby_bucket": event_match.group("bucket"),
                    "reason": event_match.group("reason"),
                    "shortcut_id": event_match.group("shortcut"),
                    "raw_line": line_str,
                }

                readable_label = event_label.replace("_", " ").title()
                artifacts.append(
                    ParsedArtifact(
                        category="application",
                        subtype="app_usage_event",
                        title=f"{package}: {readable_label}",
                        summary=(
                            f"App {package} triggered {readable_label}"
                            + (f" ({activity_class})" if activity_class else "")
                        ),
                        event_time=event_time,
                        source_locator=f"{context.input_locator}#line:{line_no}",
                        status="active",
                        confidence="high",
                        metadata={k: v for k, v in metadata.items() if v is not None},
                    )
                )
                continue

            # 2. Parse Aggregate Package Lines
            if line_str.startswith("package=") or " package=" in line_str:
                tokens = {
                    m.group(1): (m.group(2) if m.group(2) is not None else m.group(3))
                    for m in _KV_TOKEN_RE.finditer(line_str)
                }
                pkg_name = tokens.get("package")
                total_time = tokens.get("totalTime") or tokens.get("totalTimeActive")
                launch_count = tokens.get("appLaunchCount") or tokens.get("launchCount")
                last_time_str = tokens.get("lastTime") or tokens.get("lastTimeUsed")

                if pkg_name and (total_time or launch_count or last_time_str):
                    is_usagestats_dump = True
                    event_time = _parse_dumpsys_timestamp(last_time_str)

                    metadata = {
                        "package": pkg_name,
                        "total_time": total_time,
                        "launch_count": int(launch_count)
                        if launch_count and launch_count.isdigit()
                        else launch_count,
                        "last_time": last_time_str,
                        "raw_line": line_str,
                    }

                    summary_parts: list[str] = [f"Package {pkg_name}"]
                    if total_time:
                        summary_parts.append(f"active {total_time}")
                    if launch_count:
                        summary_parts.append(f"launched {launch_count} times")

                    artifacts.append(
                        ParsedArtifact(
                            category="application",
                            subtype="app_usage_summary",
                            title=f"App Usage Summary: {pkg_name}",
                            summary=", ".join(summary_parts),
                            event_time=event_time,
                            source_locator=f"{context.input_locator}#line:{line_no}",
                            status="active",
                            confidence="high",
                            metadata={k: v for k, v in metadata.items() if v is not None},
                        )
                    )

        if not is_usagestats_dump and not artifacts:
            raise AndroidDocumentParserError(
                "The file does not contain recognized Android dumpsys usagestats data."
            )

        return artifacts
