"""Tests for Android Agent APK Python orchestrator: result deserializers, installer, collector."""

from __future__ import annotations

import asyncio
from pathlib import Path

from forensix_forensic.extractors.agent_apk import (
    AgentCollector,
    AgentInstaller,
    AgentInstallerConfig,
    CollectorConfig,
    call_logs_from_json,
    contacts_from_json,
    installed_apps_from_json,
    sms_from_json,
)


class FakeAdbClient:
    """Fake ADB client for testing Agent installer and collector."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.pulled: list[tuple[str, str]] = []

    async def shell(self, serial: str, cmd: str) -> str:
        self.commands.append(cmd)
        if "test -f" in cmd:
            return "YES"
        return ""

    async def pull(self, serial: str, remote: str, local: str) -> None:
        self.pulled.append((remote, local))
        path = Path(local)
        path.parent.mkdir(parents=True, exist_ok=True)
        if "contacts.json" in remote:
            content = (
                '[{"name": "Alice", "phone_numbers": ["123"], '
                '"emails": [], "account_type": "phone"}]'
            )
            path.write_text(content, encoding="utf-8")  # noqa: ASYNC240
        elif "sms.json" in remote:
            content = (
                '[{"address": "123", "body": "Hello", "date_ms": 1000, "type": 1, "thread_id": 1}]'
            )
            path.write_text(content, encoding="utf-8")  # noqa: ASYNC240
        elif "call_logs.json" in remote:
            content = (
                '[{"number": "123", "type": 1, "date_ms": 1000, '
                '"duration_seconds": 30, "name": "Alice"}]'
            )
            path.write_text(content, encoding="utf-8")  # noqa: ASYNC240
        elif "installed_apps.json" in remote:
            content = (
                '[{"package_name": "com.test", "app_label": "Test", '
                '"version_name": "1.0", "install_time_ms": 1000, "is_system": false}]'
            )
            path.write_text(content, encoding="utf-8")  # noqa: ASYNC240


class TestAgentApk:
    def test_json_deserializers(self) -> None:
        c_data = [
            {
                "name": "Bob",
                "phone_numbers": ["555"],
                "emails": ["b@b.com"],
                "account_type": "google",
            }
        ]
        contacts = contacts_from_json(c_data)
        assert len(contacts) == 1
        assert contacts[0].name == "Bob"

        s_data = [
            {
                "address": "555",
                "body": "Hi",
                "date_ms": 2000,
                "type": 2,
                "thread_id": 5,
            }
        ]
        sms = sms_from_json(s_data)
        assert len(sms) == 1
        assert sms[0].body == "Hi"

        cl_data = [
            {
                "number": "555",
                "type": 2,
                "date_ms": 2000,
                "duration_seconds": 60,
                "name": "Bob",
            }
        ]
        calls = call_logs_from_json(cl_data)
        assert len(calls) == 1
        assert calls[0].duration_seconds == 60

        app_data = [
            {
                "package_name": "com.app",
                "app_label": "App",
                "version_name": "2.0",
                "install_time_ms": 5000,
                "is_system": True,
            }
        ]
        apps = installed_apps_from_json(app_data)
        assert len(apps) == 1
        assert apps[0].is_system is True

    def test_installer_missing_apk(self, tmp_path: Path) -> None:
        fake_adb = FakeAdbClient()
        config = AgentInstallerConfig(apk_path=tmp_path / "missing.apk")
        installer = AgentInstaller(fake_adb, config)  # type: ignore[arg-type]
        res = asyncio.run(installer.install("serial123"))
        assert res.installed is False
        assert "not found" in (res.error_message or "")

    def test_installer_success(self, tmp_path: Path) -> None:
        fake_adb = FakeAdbClient()
        apk_file = tmp_path / "forensix_agent.apk"
        apk_file.write_bytes(b"\x50\x4b\x03\x04")  # Zip header
        config = AgentInstallerConfig(apk_path=apk_file)
        installer = AgentInstaller(fake_adb, config)  # type: ignore[arg-type]
        res = asyncio.run(installer.install("serial123"))
        assert res.installed is True
        assert res.apk_sha256 != ""

    def test_collector_success(self, tmp_path: Path) -> None:
        fake_adb = FakeAdbClient()
        config = CollectorConfig(
            staging_dir="/sdcard/forensix_out",
            poll_interval_seconds=0.01,
            max_wait_seconds=1,
        )
        collector = AgentCollector(fake_adb, config, tmp_path / "collector_out")  # type: ignore[arg-type]
        res = asyncio.run(collector.collect("serial123", "CASE-001"))
        assert res.success is True
        assert len(res.contacts) == 1
        assert res.contacts[0].name == "Alice"
        assert len(res.sms_messages) == 1
        assert res.sms_messages[0].body == "Hello"
