import os
from pathlib import Path

import pytest

from forensix_forensic.adb.discovery import AdbBinaryResolver
from forensix_forensic.adb.errors import AdbBinaryNotFoundError


def test_resolver_accepts_existing_configured_binary(tmp_path: Path) -> None:
    binary = tmp_path / "adb-test"
    binary.touch()

    assert AdbBinaryResolver(binary).resolve() == binary.resolve()


def test_resolver_rejects_missing_configured_binary(tmp_path: Path) -> None:
    missing = tmp_path / "missing-adb"

    with pytest.raises(AdbBinaryNotFoundError) as caught:
        AdbBinaryResolver(missing).resolve()

    assert caught.value.code == "ADB_NOT_FOUND"


@pytest.mark.skipif(os.name != "nt", reason="Windows SDK location test")
def test_resolver_discovers_standard_windows_sdk_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk_adb = tmp_path / "Android" / "Sdk" / "platform-tools" / "adb.exe"
    sdk_adb.parent.mkdir(parents=True)
    sdk_adb.touch()
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda _: None)

    assert AdbBinaryResolver().resolve() == sdk_adb.resolve()
