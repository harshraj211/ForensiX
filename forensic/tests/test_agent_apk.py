"""Tests for Android Agent APK Python orchestrator: result deserializers, installer, collector."""

from __future__ import annotations

import asyncio
from pathlib import Path

from forensix_forensic.extractors.agent_apk import (
    AgentCollector,
    AgentInstaller,
    AgentInstallerConfig,
    CollectorConfig,
    app_artifacts_from_json,
    call_logs_from_json,
    contacts_from_json,
    device_metadata_from_json,
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
        elif "device_metadata.json" in remote:
            content = (
                '{"source": "android_agent", "category": "device_metadata", '
                '"collected_at_ms": 1700000000000, '
                '"data": {"manufacturer": "Google", "model": "Pixel 7", "sdk_level": 33}, '
                '"availability_map": {'
                '"manufacturer": "available", "model": "available", "sdk_level": "available"}}'
            )
            path.write_text(content, encoding="utf-8")  # noqa: ASYNC240
        elif "app_artifacts.json" in remote:
            content = (
                '[{"package_name": "com.whatsapp", "artifact_category": "user_backup", '
                '"relative_path": "/WhatsApp/Databases/msgstore.db.crypt14", '
                '"absolute_path": "/sdcard/WhatsApp/Databases/msgstore.db.crypt14", '
                '"size_bytes": 1048576, "last_modified_ms": 1700000000000, '
                '"mime_type": "application/octet-stream", "sha256_hash": "", '
                '"accessibility_status": "available"}, '
                '{"package_name": "com.whatsapp", "artifact_category": "media", '
                '"relative_path": "/WhatsApp/Media/IMG_001.jpg", '
                '"absolute_path": "/sdcard/WhatsApp/Media/IMG_001.jpg", '
                '"size_bytes": 524288, "last_modified_ms": 1700000000000, '
                '"mime_type": "image/jpeg", "sha256_hash": "", '
                '"accessibility_status": "available"}]'
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

    def test_metadata_deserializer_normal(self) -> None:
        """Test A: Normal metadata collection and deserialization."""
        meta_json = {
            "source": "android_agent",
            "category": "device_metadata",
            "collected_at_ms": 1700000000000,
            "data": {
                "manufacturer": "Google",
                "model": "Pixel 7",
                "android_release": "13",
                "sdk_level": 33,
                "build_fingerprint": "google/panther/panther:13/TQ3A.230805.001",
                "security_patch": "2023-08-01",
                "cpu_abi": "arm64-v8a",
                "supported_abis": ["arm64-v8a"],
                "encryption_state": "file",
                "verified_boot_state": "green",
                "bootloader_state": "locked",
                "is_debuggable": False,
                "uptime_ms": 1234567,
                "locale": "en_US",
                "timezone": "America/New_York",
                "battery_level": 85,
                "charging_state": "discharging",
                "battery_status": "none",
                "storage_total_bytes": 128000000000,
                "storage_available_bytes": 64000000000,
            },
            "availability_map": {
                "manufacturer": "available",
                "model": "available",
                "sdk_level": "available",
                "battery_level": "available",
            },
        }
        meta = device_metadata_from_json(meta_json)
        assert meta is not None
        assert meta.source == "android_agent"
        assert meta.category == "device_metadata"
        assert meta.data["manufacturer"] == "Google"
        assert meta.data["sdk_level"] == 33
        assert meta.availability_map["manufacturer"] == "available"

    def test_metadata_deserializer_missing_and_restricted(self) -> None:
        """Test B & C: Missing & restricted properties produce explicit unavailable states."""
        meta_json = {
            "source": "android_agent",
            "category": "device_metadata",
            "collected_at_ms": 1700000000000,
            "data": {
                "manufacturer": "Samsung",
                "serial_number": None,
                "imei": None,
            },
            "availability_map": {
                "manufacturer": "available",
                "serial_number": "restricted",
                "imei": "restricted",
                "security_patch": "unavailable",
            },
        }
        meta = device_metadata_from_json(meta_json)
        assert meta is not None
        assert meta.data["serial_number"] is None
        assert meta.availability_map["serial_number"] == "restricted"
        assert meta.availability_map["security_patch"] == "unavailable"

    def test_metadata_deserializer_malformed(self) -> None:
        """Test D: Malformed non-dict JSON structures do not crash."""
        assert device_metadata_from_json(None) is None
        assert device_metadata_from_json("invalid_json_string") is None  # type: ignore[arg-type]
        assert device_metadata_from_json([]) is None  # type: ignore[arg-type]

    def test_metadata_deserializer_partial_failure(self) -> None:
        """Test E: Partial field errors do not abort parsing of other fields."""
        meta_json = {
            "source": "android_agent",
            "category": "device_metadata",
            "collected_at_ms": 1700000000000,
            "data": {
                "manufacturer": "Xiaomi",
                "model": "Redmi 9",
                "battery_level": -1,
            },
            "availability_map": {
                "manufacturer": "available",
                "model": "available",
                "battery_level": "error",
            },
        }
        meta = device_metadata_from_json(meta_json)
        assert meta is not None
        assert meta.data["manufacturer"] == "Xiaomi"
        assert meta.availability_map["battery_level"] == "error"

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

    def test_app_intelligence_and_surfaces(self) -> None:
        """Test A, B, C, F: Package metadata, version codes, UIDs, perms, and surfaces."""
        app_json = [
            {
                "package_name": "com.whatsapp",
                "app_label": "WhatsApp",
                "version_name": "2.23.20.76",
                "version_code": 232076000,
                "install_time_ms": 1690000000000,
                "last_update_time_ms": 1700000000000,
                "is_system": False,
                "uid": 10145,
                "target_sdk": 33,
                "min_sdk": 21,
                "is_enabled": True,
                "is_debuggable": False,
                "allow_backup": True,
                "source_dir": "/data/app/~~xyz==/com.whatsapp-abc==/base.apk",
                "installer_package": "com.android.vending",
                "requested_permissions": ["android.permission.READ_CONTACTS"],
                "granted_permissions": ["android.permission.READ_CONTACTS"],
                "surfaces": {
                    "private_app_storage": "restricted",
                    "shared_storage": "available",
                    "media": "available",
                    "app_export": "available",
                    "system_api": "available",
                    "ui_access": "not_configured",
                    "backup_surface": "available",
                },
            }
        ]
        apps = installed_apps_from_json(app_json)
        assert len(apps) == 1
        app = apps[0]
        assert app.package_name == "com.whatsapp"
        assert app.version_code == 232076000
        assert app.uid == 10145
        assert app.target_sdk == 33
        assert app.allow_backup is True
        assert app.surfaces["private_app_storage"] == "restricted"
        assert app.surfaces["shared_storage"] == "available"

    def test_app_artifacts_discovery(self) -> None:
        """Test D & E: Shared storage, backup, export, and media artifact discovery."""
        artifacts_json = [
            {
                "package_name": "com.whatsapp",
                "artifact_category": "user_backup",
                "relative_path": "/WhatsApp/Databases/msgstore.db.crypt14",
                "absolute_path": "/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
                "size_bytes": 2048000,
                "last_modified_ms": 1700000000000,
                "mime_type": "application/octet-stream",
                "sha256_hash": "",
                "accessibility_status": "available",
            },
            {
                "package_name": "com.whatsapp",
                "artifact_category": "media",
                "relative_path": "/WhatsApp/Media/WhatsApp Images/IMG_001.jpg",
                "absolute_path": "/sdcard/WhatsApp/Media/WhatsApp Images/IMG_001.jpg",
                "size_bytes": 1024000,
                "last_modified_ms": 1700000000000,
                "mime_type": "image/jpeg",
                "sha256_hash": "",
                "accessibility_status": "available",
            },
        ]
        artifacts = app_artifacts_from_json(artifacts_json)
        assert len(artifacts) == 2
        assert artifacts[0].package_name == "com.whatsapp"
        assert artifacts[0].artifact_category == "user_backup"
        assert artifacts[1].artifact_category == "media"

    def test_app_artifacts_partial_failure(self) -> None:
        """Test G: Non-list or malformed items degrade gracefully."""
        assert app_artifacts_from_json(None) == ()  # type: ignore[arg-type]
        assert app_artifacts_from_json("invalid") == ()  # type: ignore[arg-type]
        artifacts = app_artifacts_from_json([None, "string", {"package_name": "com.valid"}])  # type: ignore[list-item]
        assert len(artifacts) == 1
        assert artifacts[0].package_name == "com.valid"

    def test_collector_success(self, tmp_path: Path) -> None:
        """Test H & I: Collector pulls apps, artifacts, and retains backward compatibility."""
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
        assert res.device_metadata is not None
        assert res.device_metadata.data["manufacturer"] == "Google"
        assert len(res.app_artifacts) == 2
        assert res.media_file_count == 1
        assert res.app_artifacts[0].package_name == "com.whatsapp"
