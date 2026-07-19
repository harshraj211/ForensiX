import sys
from hashlib import sha256
from pathlib import Path

import pytest

from forensix_forensic.integrations import (
    AleappConfiguration,
    AleappExecutionError,
    AleappRunner,
)


def _program(tmp_path: Path, body: str) -> tuple[Path, str]:
    program = tmp_path / "aleapp.py"
    program.write_text(body, encoding="utf-8")
    return program, sha256(program.read_bytes()).hexdigest()


def test_pinned_aleapp_adapter_runs_shell_free_and_hashes_outputs(tmp_path: Path) -> None:
    program, digest = _program(
        tmp_path,
        """
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('-t')
parser.add_argument('-i')
parser.add_argument('-o')
args = parser.parse_args()
output = Path(args.o)
output.mkdir(parents=True, exist_ok=True)
(output / 'report.tsv').write_text('header\\nknown-answer\\n', encoding='utf-8')
print(f'processed:{args.t}')
""",
    )
    source = tmp_path / "source.zip"
    source.write_bytes(b"controlled fixture")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = AleappRunner(
        AleappConfiguration(
            program_path=program,
            python_executable=Path(sys.executable),
            expected_sha256=digest,
            release_label="v2026.1.0",
            timeout_seconds=5,
        )
    )

    diagnostic = runner.diagnose()
    result = runner.run(source, workspace / "output", workspace, input_type="zip")

    assert diagnostic.available and diagnostic.hash_verified
    assert result.exit_code == 0
    assert result.stdout.strip() == "processed:zip"
    assert result.outputs[0].relative_path == "report.tsv"
    output_bytes = (workspace / "output" / "report.tsv").read_bytes()
    assert output_bytes.decode().splitlines() == ["header", "known-answer"]
    assert result.outputs[0].sha256 == sha256(output_bytes).hexdigest()


def test_aleapp_adapter_rejects_unpinned_program(tmp_path: Path) -> None:
    program, _ = _program(tmp_path, "print('unexpected')")
    source = tmp_path / "source.zip"
    source.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = AleappRunner(
        AleappConfiguration(
            program_path=program,
            python_executable=Path(sys.executable),
            expected_sha256="0" * 64,
            release_label="v2026.1.0",
        )
    )

    assert not runner.diagnose().hash_verified
    with pytest.raises(AleappExecutionError, match="does not match"):
        runner.run(source, workspace / "output", workspace, input_type="zip")


def test_aleapp_adapter_enforces_timeout(tmp_path: Path) -> None:
    program, digest = _program(tmp_path, "import time\ntime.sleep(5)\n")
    source = tmp_path / "source.zip"
    source.write_bytes(b"fixture")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = AleappRunner(
        AleappConfiguration(
            program_path=program,
            python_executable=Path(sys.executable),
            expected_sha256=digest,
            release_label="v2026.1.0",
            timeout_seconds=0.1,
        )
    )

    with pytest.raises(AleappExecutionError, match="timeout"):
        runner.run(source, workspace / "output", workspace, input_type="zip")
