"""Create a sealed, privacy-preserving ADB validation record."""

import argparse
import asyncio
import json
from pathlib import Path

from forensix_forensic.adb import (
    AdbBinaryResolver,
    AdbClient,
    MockAdbClient,
    MockAdbScenario,
    SubprocessAdbRunner,
    SystemAdbClient,
)
from forensix_forensic.validation import run_adb_validation


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("mock", "system"), default="mock")
    parser.add_argument("--scenario", choices=tuple(MockAdbScenario), default="authorized")
    parser.add_argument("--adb-path", type=Path)
    parser.add_argument(
        "--serial", help="Select one authorized serial; it is never written to output."
    )
    parser.add_argument(
        "--validate-known-file",
        action="store_true",
        help="Pull the one fixed controlled-device fixture twice and verify its SHA-256.",
    )
    parser.add_argument(
        "--validate-transport-cycle",
        action="store_true",
        help="Interactively observe disconnect, reconnect, and fixed-file reacquisition.",
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


async def _run(arguments: argparse.Namespace) -> int:
    if arguments.validate_transport_cycle and not arguments.validate_known_file:
        raise ValueError("--validate-transport-cycle requires --validate-known-file")
    if arguments.mode == "mock":
        client: AdbClient = MockAdbClient(
            MockAdbScenario(arguments.scenario),
            include_validation_fixture=arguments.validate_known_file,
        )
    else:
        adb_path = AdbBinaryResolver(arguments.adb_path).resolve()
        client = SystemAdbClient(SubprocessAdbRunner(adb_path))
    sealed = await run_adb_validation(
        client,
        mode=arguments.mode,
        selected_serial=arguments.serial,
        validate_known_file=arguments.validate_known_file,
        validate_transport_cycle=arguments.validate_transport_cycle,
        checkpoint=_operator_checkpoint if arguments.validate_transport_cycle else None,
    )
    destination = arguments.output.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.partial")
    temporary.write_text(
        json.dumps(sealed.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    print(f"Validation outcome: {sealed.report.outcome.value}")
    print(f"Report SHA-256: {sealed.canonical_sha256}")
    print(f"Written: {destination}")
    return 0 if sealed.report.outcome.value.startswith("passed") else 2


async def _operator_checkpoint(step: str) -> None:
    prompts = {
        "disconnect": (
            "Disconnect the selected controlled-device ADB transport, then press Enter. "
            "For wired validation, unplug the USB cable: "
        ),
        "reconnect": (
            "Reconnect the same controlled device, unlock it, restore ADB authorization, then "
            "press Enter: "
        ),
    }
    await asyncio.to_thread(input, prompts[step])


def main() -> int:
    return asyncio.run(_run(_arguments()))


if __name__ == "__main__":
    raise SystemExit(main())
