"""Tests for cloud extractors: Google Takeout, WhatsApp Cloud, and CloudBackupRouter."""

from __future__ import annotations

import asyncio
from pathlib import Path

from forensix_forensic.extractors.cloud import (
    CloudBackupRouter,
    CloudTokenBundle,
    GoogleBackupToken,
    GoogleTakeoutDownloader,
    WhatsAppCloudDownloader,
    WhatsAppCloudToken,
)


class TestCloudExtractors:
    def test_google_takeout_downloader(self, tmp_path: Path) -> None:
        downloader = GoogleTakeoutDownloader(tmp_path / "google")
        token = GoogleBackupToken(
            account_email="test@gmail.com",
            auth_token="ya29.test_token",
            gsf_id="1234567890abcdef",
            device_id="device_001",
        )
        res = asyncio.run(downloader.download(token, "CASE-001", "examiner"))
        assert res.success is True
        assert res.account_email == "test@gmail.com"
        assert len(res.backup_files) == 1
        assert res.aggregate_sha256 != ""

    def test_whatsapp_cloud_downloader(self, tmp_path: Path) -> None:
        downloader = WhatsAppCloudDownloader(tmp_path / "whatsapp")
        token = WhatsAppCloudToken(
            google_auth_token="ya29.drive_token",
            whatsapp_jid="15551234567@s.whatsapp.net",
            account_email="test@gmail.com",
        )
        res = asyncio.run(downloader.download(token, "CASE-001", "examiner"))
        assert res.success is True
        assert res.jid == "15551234567@s.whatsapp.net"
        assert res.backup_file is not None
        assert res.metadata_file is not None

    def test_cloud_backup_router(self, tmp_path: Path) -> None:
        router = CloudBackupRouter(tmp_path / "cloud_router")
        g_token = GoogleBackupToken(
            account_email="user@gmail.com",
            auth_token="token123",
            gsf_id="gsf123",
            device_id="dev123",
        )
        w_token = WhatsAppCloudToken(
            google_auth_token="token123",
            whatsapp_jid="15559876543@s.whatsapp.net",
            account_email="user@gmail.com",
        )
        bundle = CloudTokenBundle(google_token=g_token, whatsapp_token=w_token)
        res = asyncio.run(router.download_all(bundle, "CASE-001", "examiner"))
        assert res.success is True
        assert res.google_result is not None
        assert res.whatsapp_result is not None
