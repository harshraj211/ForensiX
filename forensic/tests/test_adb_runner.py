import sys
from pathlib import Path

import pytest

from forensix_forensic.adb.errors import (
    AdbOutputLimitError,
    AdbTimeoutError,
    AdbTransferLimitError,
)
from forensix_forensic.adb.runner import SubprocessAdbRunner


@pytest.mark.asyncio
async def test_runner_times_out_and_terminates_process() -> None:
    runner = SubprocessAdbRunner(Path(sys.executable), default_timeout_seconds=0.05)

    with pytest.raises(AdbTimeoutError):
        await runner.run(("-c", "import time; time.sleep(2)"))


@pytest.mark.asyncio
async def test_runner_limits_output() -> None:
    runner = SubprocessAdbRunner(Path(sys.executable), output_limit_bytes=32)

    with pytest.raises(AdbOutputLimitError):
        await runner.run(
            ("-u", "-c", "import sys; sys.stdout.write('x' * 1000); sys.stdout.flush()"),
            timeout_seconds=30,
        )


@pytest.mark.asyncio
async def test_runner_returns_structured_result() -> None:
    runner = SubprocessAdbRunner(Path(sys.executable))

    result = await runner.run(("-c", "print('ok')"))

    assert result.exit_code == 0
    assert result.stdout.strip() == "ok"
    assert result.argv == ("-c", "print('ok')")


@pytest.mark.asyncio
async def test_runner_stops_pull_when_partial_exceeds_limit(tmp_path: Path) -> None:
    runner = SubprocessAdbRunner(Path(sys.executable))
    destination = tmp_path / "oversized.partial"
    script = (
        "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_bytes(b'x'*4096); time.sleep(2)"
    )

    with pytest.raises(AdbTransferLimitError):
        await runner.run_to_file(
            ("-c", script, str(destination)),
            destination,
            timeout_seconds=3,
            max_file_bytes=32,
        )


@pytest.mark.asyncio
async def test_runner_streams_binary_stdout_directly_to_new_file(tmp_path: Path) -> None:
    runner = SubprocessAdbRunner(Path(sys.executable))
    destination = tmp_path / "bundle.partial"

    result = await runner.run_stdout_to_file(
        ("-c", "import sys; sys.stdout.buffer.write(bytes(range(256)))"),
        destination,
        timeout_seconds=3,
        max_file_bytes=512,
    )

    assert result.exit_code == 0
    assert result.stdout == ""
    assert destination.read_bytes() == bytes(range(256))


@pytest.mark.asyncio
async def test_runner_limits_binary_stdout_file(tmp_path: Path) -> None:
    runner = SubprocessAdbRunner(Path(sys.executable))
    destination = tmp_path / "oversized-bundle.partial"

    with pytest.raises(AdbTransferLimitError):
        await runner.run_stdout_to_file(
            ("-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"),
            destination,
            timeout_seconds=3,
            max_file_bytes=32,
        )
