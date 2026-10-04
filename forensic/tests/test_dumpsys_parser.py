"""Tests for Android non-rooted dumpsys usagestats parser."""

from pathlib import Path

import pytest

from forensix_forensic.android_artifacts import (
    AndroidDocumentParserError,
    AndroidDumpsysUsageStatsParser,
    android_document_parser_registry,
)
from forensix_forensic.evidence_io import ParserContext


def _context(locator: str) -> ParserContext:
    return ParserContext(
        case_id="case-100",
        evidence_source_id="source-100",
        working_copy_id="copy-100",
        source_sha256="0" * 64,
        source_label=locator,
        input_locator=locator,
        input_sha256="1" * 64,
    )


def test_dumpsys_usagestats_parser_parses_events_and_aggregates(tmp_path: Path) -> None:
    sample_dumpsys = """
In-memory event log
  time="2026-03-01 14:22:10" type=MOVE_TO_FOREGROUND package=com.whatsapp class=com.whatsapp.HomeActivity flags=0x0
  time="2026-03-01 14:25:40" type=MOVE_TO_BACKGROUND package=com.whatsapp class=com.whatsapp.HomeActivity flags=0x0
  time="2026-03-01 14:26:01" type=USER_INTERACTION package=org.telegram.messenger class=org.telegram.ui.LaunchActivity
  time="2026-03-01 14:26:05" type=1 package=org.telegram.messenger class=org.telegram.ui.LaunchActivity flags=0x0
  time="2026-03-01 14:30:12" type=STANDBY_BUCKET_CHANGED package=com.google.android.youtube standbyBucket=10 reason=u-f
  time="2026-03-01 14:31:00" type=SHORTCUT_INVOCATION package=com.google.android.gm shortcutId=compose

User 0
  daily
    package=com.whatsapp totalTime="01:25:34" lastTime="2026-03-01 14:25:40" appLaunchCount=15
    package=org.telegram.messenger totalTime="00:45:12" lastTime="2026-03-01 14:26:05" appLaunchCount=8
    package=com.android.chrome totalTime="02:15:10" lastTime="2026-03-01 12:00:00" appLaunchCount=22
"""
    path = tmp_path / "dumpsys_usagestats.txt"
    path.write_text(sample_dumpsys, encoding="utf-8")

    parser = AndroidDumpsysUsageStatsParser()
    assert parser.can_parse("dumpsys_usagestats.txt")
    assert parser.can_parse("/data/local/tmp/usagestats.txt")
    assert parser.can_parse("triage/adb_dumpsys.txt")

    artifacts = parser.parse(path, _context(path.name))
    assert len(artifacts) == 9  # 6 events + 3 aggregate summaries

    # Verify event artifacts
    whatsapp_fg = next(
        a
        for a in artifacts
        if a.subtype == "app_usage_event" and a.metadata.get("package") == "com.whatsapp"
    )
    assert whatsapp_fg.title == "com.whatsapp: Move To Foreground"
    assert whatsapp_fg.event_time is not None
    assert whatsapp_fg.event_time.year == 2026
    assert whatsapp_fg.event_time.month == 3
    assert whatsapp_fg.event_time.day == 1
    assert whatsapp_fg.metadata["class"] == "com.whatsapp.HomeActivity"
    assert whatsapp_fg.metadata["event_type"] == "MOVE_TO_FOREGROUND"

    # Verify numeric event code mapping (type=1 -> MOVE_TO_FOREGROUND)
    telegram_num_fg = [
        a
        for a in artifacts
        if a.subtype == "app_usage_event"
        and a.metadata.get("package") == "org.telegram.messenger"
        and a.metadata.get("event_type") == "MOVE_TO_FOREGROUND"
    ]
    assert len(telegram_num_fg) == 1
    assert telegram_num_fg[0].title == "org.telegram.messenger: Move To Foreground"

    # Verify aggregate summaries
    aggregates = [a for a in artifacts if a.subtype == "app_usage_summary"]
    assert len(aggregates) == 3

    wa_agg = next(a for a in aggregates if a.metadata["package"] == "com.whatsapp")
    assert wa_agg.title == "App Usage Summary: com.whatsapp"
    assert wa_agg.metadata["total_time"] == "01:25:34"
    assert wa_agg.metadata["launch_count"] == 15
    assert wa_agg.event_time is not None
    assert wa_agg.event_time.hour == 14
    assert wa_agg.event_time.minute == 25


def test_dumpsys_usagestats_registry_integration() -> None:
    registry = android_document_parser_registry()
    compatible = registry.compatible("dumpsys_usagestats.txt")
    assert any(p.metadata.parser_id == "android.dumpsys.usagestats" for p in compatible)


def test_dumpsys_usagestats_rejects_unrelated_text(tmp_path: Path) -> None:
    path = tmp_path / "usagestats.txt"
    path.write_text(
        "This is an unrelated arbitrary log file with no android usage data.\nNothing here.",
        encoding="utf-8",
    )

    parser = AndroidDumpsysUsageStatsParser()
    with pytest.raises(
        AndroidDocumentParserError, match="not contain recognized Android dumpsys usagestats"
    ):
        parser.parse(path, _context(path.name))
