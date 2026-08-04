import hashlib
import subprocess
from pathlib import Path

from pytest import MonkeyPatch

from forensix_forensic.integrations.photorec import (
    PhotoRecConfiguration,
    PhotoRecController,
)


def test_pinned_photorec_runs_only_with_redacted_manifest_paths(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "photorec.exe"
    executable.write_bytes(b"controlled photorec binary")
    source = tmp_path / "working-copy.img"
    source.write_bytes(b"working-copy")
    output = tmp_path / "output"
    seen: list[list[str]] = []

    def fake_run(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        seen.append(arguments)
        if arguments[1:] == ["/version"]:
            return subprocess.CompletedProcess(arguments, 0, "PhotoRec 7.2", "")
        destination = Path(arguments[arguments.index("/d") + 1])
        recovered = Path(f"{destination}.1")
        recovered.mkdir(parents=True)
        (recovered / "f0000001.jpg").write_bytes(b"candidate media")
        return subprocess.CompletedProcess(arguments, 0, "Recovered 1 file", "")

    monkeypatch.setattr("forensix_forensic.integrations.photorec.subprocess.run", fake_run)
    controller = PhotoRecController(
        PhotoRecConfiguration(
            program_path=executable,
            expected_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        )
    )

    execution = controller.recover(source, output)

    assert execution.exit_code == 0
    assert execution.version == "7.2"
    assert execution.output_files[0].relative_path == "recovered.1/f0000001.jpg"
    assert str(source) not in execution.command
    assert str(output) not in execution.command
    assert seen[-1][seen[-1].index("/cmd") + 1] == str(source)


def test_photorec_rejects_unpinned_executable(tmp_path: Path) -> None:
    executable = tmp_path / "photorec.exe"
    executable.write_bytes(b"untrusted")
    controller = PhotoRecController(
        PhotoRecConfiguration(program_path=executable, expected_sha256=None)
    )

    diagnostic = controller.diagnose()

    assert diagnostic.available is False
    assert diagnostic.status == "untrusted"
