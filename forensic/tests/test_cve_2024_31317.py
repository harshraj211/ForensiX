"""Tests for CVE-2024-31317 targeted filesystem extractor."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from forensix_forensic.extractors.cve_2024_31317 import (
    CVE202431317Extractor,
)


@pytest.mark.asyncio
async def test_cve_2024_31317_assess_vulnerable(tmp_path: Path) -> None:
    mock_adb = AsyncMock()
    mock_adb.get_properties.return_value = {
        "ro.build.version.security_patch": "2024-05-05",
        "ro.build.version.release": "14",
    }

    extractor = CVE202431317Extractor(mock_adb, tmp_path)
    vulnerable, spl, reason = await extractor.assess_capability("TEST_SERIAL")

    assert vulnerable is True
    assert spl == "2024-05-05"
    assert "vulnerable" in reason


@pytest.mark.asyncio
async def test_cve_2024_31317_assess_patched(tmp_path: Path) -> None:
    mock_adb = AsyncMock()
    mock_adb.get_properties.return_value = {
        "ro.build.version.security_patch": "2024-07-01",
        "ro.build.version.release": "14",
    }

    extractor = CVE202431317Extractor(mock_adb, tmp_path)
    vulnerable, spl, reason = await extractor.assess_capability("TEST_SERIAL")

    assert vulnerable is False
    assert spl == "2024-07-01"
    assert "patched" in reason


@pytest.mark.asyncio
async def test_cve_2024_31317_extract_success(tmp_path: Path) -> None:
    mock_adb = AsyncMock()
    mock_adb.get_properties.return_value = {
        "ro.build.version.security_patch": "2024-04-01",
        "ro.build.version.release": "13",
    }

    extractor = CVE202431317Extractor(mock_adb, tmp_path)
    res = await extractor.extract("SERIAL_123", case_id="CASE_001", operator_id="OP_1")

    assert res.success is True
    assert res.vulnerable is True
    assert res.security_patch_level == "2024-04-01"
    assert res.partition_name == "userdata"
    assert res.image_file_path is not None
    assert res.image_size_bytes > 0
    assert len(res.image_sha256) == 64
    assert len(res.timeline) > 0
