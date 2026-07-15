import sys
from pathlib import Path

import pytest

from forensix_forensic.adb.errors import AdbOutputLimitError, AdbTimeoutError
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
        await runner.run(("-c", "print('x' * 1000)"))


@pytest.mark.asyncio
async def test_runner_returns_structured_result() -> None:
    runner = SubprocessAdbRunner(Path(sys.executable))

    result = await runner.run(("-c", "print('ok')"))

    assert result.exit_code == 0
    assert result.stdout.strip() == "ok"
    assert result.argv == ("-c", "print('ok')")
