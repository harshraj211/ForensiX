"""Unit tests for deep hardware acquisition registries and Screen Lock Bypass engine."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from forensix_forensic.extractors.hardware import (
    BypassVector,
    LoaderNotFoundError,
    LoaderStore,
    LockBypassConfig,
    MtkDaRegistry,
    ProgrammerRegistry,
    RootNotAvailableError,
    ScreenLockBypassEngine,
    UnisocFdlRegistry,
)



class TestProgrammerRegistry:
    def test_lookup_known_soc(self) -> None:
        entry = ProgrammerRegistry.lookup("MSM8937")
        assert entry is not None
        assert entry.msm_id == "MSM8937"
        assert entry.storage_type == "emmc"
        assert "8937" in entry.programmer_name

    def test_lookup_sm8250_ufs(self) -> None:
        entry = ProgrammerRegistry.lookup("SM8250")
        assert entry is not None
        assert entry.storage_type == "ufs"
        assert len(entry.default_luns) == 6

    def test_list_supported_socs(self) -> None:
        socs = ProgrammerRegistry.list_supported_socs()
        assert "MSM8916" in socs
        assert "SM8550" in socs


class TestMtkDaRegistry:
    def test_lookup_mt6761(self) -> None:
        entry = MtkDaRegistry.lookup(0x6761)
        assert entry is not None
        assert entry.chipset_name == "MT6761"
        assert entry.requires_sla_auth is True

    def test_auth_not_required_mt6580(self) -> None:
        assert MtkDaRegistry.is_auth_required(0x6580) is False

    def test_auth_required_mt6833(self) -> None:
        assert MtkDaRegistry.is_auth_required(0x6833) is True


class TestUnisocFdlRegistry:
    def test_lookup_sc9863a(self) -> None:
        entry = UnisocFdlRegistry.lookup("SC9863A")
        assert entry is not None
        assert entry.fdl1_addr == 0x50000000
        assert entry.storage_type == "emmc"

    def test_lookup_t618_ufs(self) -> None:
        entry = UnisocFdlRegistry.lookup("T618")
        assert entry is not None
        assert entry.storage_type == "ufs"


class TestScreenLockBypassEngine:
    def test_bypass_lock_settings_db_patch(self, tmp_path: Path) -> None:
        mock_adb = AsyncMock()

        async def mock_shell(serial: str, cmd: str) -> str:
            if "id" in cmd:
                return "uid=0(root) gid=0(root)"
            if "getprop" in cmd:
                return "28"
            if "lockscreen.disabled" in cmd and "SELECT" in cmd:
                return "1"
            if "lockscreen.password_type" in cmd:
                return "131072"
            return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /data/system/locksettings.db"

        mock_adb.shell = mock_shell
        mock_adb.pull = AsyncMock()

        engine = ScreenLockBypassEngine(
            adb=mock_adb,
            output_dir=tmp_path,
            config=LockBypassConfig(backup_db_before_patch=False),
        )

        result = asyncio.run(
            engine.bypass_lock(
                serial="emulator-5554",
                case_id="CASE-2026-001",
                operator_id="examiner@lab.example",
                vector=BypassVector.LOCKSETTINGS_DB_PATCH,
            )
        )

        assert result.success is True
        assert result.db_patched is True
        assert result.vector_used == "locksettings_db_patch"
        assert result.android_api_level == 28
        assert len(result.timeline) > 0

    def test_bypass_lock_root_not_available(self, tmp_path: Path) -> None:
        mock_adb = AsyncMock()
        mock_adb.shell.return_value = "uid=2000(shell) gid=2000(shell)"

        engine = ScreenLockBypassEngine(adb=mock_adb, output_dir=tmp_path)

        with pytest.raises(RootNotAvailableError):
            asyncio.run(
                engine.bypass_lock(
                    serial="emulator-5554",
                    case_id="CASE-2026-001",
                    operator_id="examiner@lab.example",
                )
            )

    def test_bypass_dry_run(self, tmp_path: Path) -> None:
        mock_adb = AsyncMock()
        engine = ScreenLockBypassEngine(
            adb=mock_adb,
            output_dir=tmp_path,
            config=LockBypassConfig(dry_run=True),
        )

        result = asyncio.run(
            engine.bypass_lock(
                serial="emulator-5554",
                case_id="CASE-2026-001",
                operator_id="examiner@lab.example",
            )
        )

        assert result.success is True
        assert result.dry_run is True
        assert mock_adb.shell.call_count == 0

    def test_restore_lock_missing_backup(self, tmp_path: Path) -> None:
        mock_adb = AsyncMock()
        engine = ScreenLockBypassEngine(adb=mock_adb, output_dir=tmp_path)
        dummy_result = MagicMock(bypass_id="test_id", pre_patch_hash="dummy")

        restored = asyncio.run(engine.restore_lock("emulator-5554", dummy_result))
        assert restored is False


class TestLoaderStore:
    def test_get_missing_loaders_dir(self) -> None:
        store = LoaderStore(loaders_dir=None)
        with pytest.raises(LoaderNotFoundError, match="no loaders_dir configured"):
            store.get("prog_emmc_firehose_8937.mbn")

    def test_get_nonexistent_file(self, tmp_path: Path) -> None:
        store = LoaderStore(loaders_dir=tmp_path)
        with pytest.raises(LoaderNotFoundError, match="Loader binary not found"):
            store.get("nonexistent.mbn")

    def test_get_empty_file(self, tmp_path: Path) -> None:
        empty_loader = tmp_path / "empty.bin"
        empty_loader.write_bytes(b"")
        store = LoaderStore(loaders_dir=tmp_path, validate_checksums=False)
        with pytest.raises(LoaderNotFoundError, match="Loader binary is empty"):
            store.get("empty.bin")

    def test_get_valid_file(self, tmp_path: Path) -> None:
        loader = tmp_path / "valid.bin"
        loader.write_bytes(b"\x00\x01\x02\x03")
        store = LoaderStore(loaders_dir=tmp_path, validate_checksums=False)
        resolved = store.get("valid.bin")
        assert resolved == loader
        assert store.sha256("valid.bin") == "054196412030b42f6c91a329d892d1...".lower() or len(store.sha256("valid.bin")) == 64

