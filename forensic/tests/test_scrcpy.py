import subprocess
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

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


def test_scrcpy_recording_is_scoped_and_stopped_by_registered_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "scrcpy.exe"
    executable.write_bytes(b"controlled scrcpy fixture")
    destination = tmp_path / "recording.mp4"
    calls: list[list[str]] = []
    process = SimpleNamespace(
        pid=5252,
        poll=lambda: None,
        terminate=lambda: None,
        wait=lambda timeout: 0,
        kill=lambda: None,
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, stdout="scrcpy 4.1\n", stderr=""
        ),
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda arguments, **kwargs: calls.append(arguments) or process,
    )
    recording_id = str(uuid4())
    controller = ScrcpyController(executable)

    launch = controller.start_recording(recording_id, "FX-DEMO-001", destination)
    stopped = controller.stop_recording(recording_id, expected_process_id=launch.process_id)

    assert calls[0][calls[0].index("--record") + 1] == str(destination.resolve())
    assert "--no-control" not in calls[0]
    assert stopped.process_id == 5252
    assert stopped.exit_code == 0
    assert stopped.already_exited is False
    with pytest.raises(ScrcpyIntegrationError, match="not active"):
        controller.stop_recording(recording_id, expected_process_id=5252)


@pytest.mark.parametrize("serial", ["", "bad serial", "bad\nserial"])
def test_scrcpy_rejects_unsafe_serial(serial: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ScrcpyController(tmp_path / "scrcpy.exe").launch(serial, control=True)
