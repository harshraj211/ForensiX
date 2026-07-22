import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensix_forensic.integrations import ScrcpyController, ScrcpyIntegrationError


def test_scrcpy_diagnostic_reports_missing_binary(tmp_path: Path) -> None:
    diagnostic = ScrcpyController(tmp_path / "missing-scrcpy.exe").diagnose()

    assert diagnostic.available is False
    assert diagnostic.status == "missing"


def test_scrcpy_launch_uses_serial_scoped_forensic_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "scrcpy.exe"
    executable.write_bytes(b"controlled scrcpy fixture")
    calls: list[list[str]] = []

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del args, kwargs
        return subprocess.CompletedProcess([], 0, stdout="scrcpy 4.1\n", stderr="")

    def fake_popen(arguments: list[str], **kwargs: object) -> SimpleNamespace:
        del kwargs
        calls.append(arguments)
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    result = ScrcpyController(executable).launch("FX-DEMO-001", control=False)

    assert result.process_id == 4242
    assert result.mode == "mirror"
    assert calls[0][1:3] == ["--serial", "FX-DEMO-001"]
    assert "--no-control" in calls[0]
    assert "--no-clipboard-autosync" in calls[0]
    assert "--no-audio" in calls[0]


def test_scrcpy_digest_mismatch_prevents_launch(tmp_path: Path) -> None:
    executable = tmp_path / "scrcpy.exe"
    executable.write_bytes(b"unexpected executable")
    controller = ScrcpyController(executable, "0" * 64)

    assert controller.diagnose().status == "digest_mismatch"
    with pytest.raises(ScrcpyIntegrationError):
        controller.launch("FX-DEMO-001", control=True)


@pytest.mark.parametrize("serial", ["", "bad serial", "bad\nserial"])
def test_scrcpy_rejects_unsafe_serial(serial: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ScrcpyController(tmp_path / "scrcpy.exe").launch(serial, control=True)
