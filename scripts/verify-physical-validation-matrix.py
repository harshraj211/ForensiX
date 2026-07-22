"""Build an integrity-sealed release gate from physical validation records."""

import argparse
import json
from pathlib import Path

from forensix_forensic.validation import (
    PhysicalMatrixPolicy,
    SealedValidationReport,
    build_physical_matrix,
)

MAX_INPUT_BYTES = 5 * 1024 * 1024


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, action="append", type=Path)
    parser.add_argument(
        "--require-host",
        action="append",
        help="Required platform.system() value; defaults to Windows, Linux, and Darwin.",
    )
    parser.add_argument("--require-android-release", required=True, action="append")
    parser.add_argument("--minimum-manufacturers", type=int, default=2)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def _load(path: Path) -> SealedValidationReport:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError(f"Validation input must not be a symlink: {expanded}")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"Validation input must be a regular non-symlink file: {resolved}")
    if resolved.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"Validation input exceeds {MAX_INPUT_BYTES} bytes: {resolved}")
    return SealedValidationReport.model_validate_json(resolved.read_bytes())


def main() -> int:
    arguments = _arguments()
    records = tuple(_load(path) for path in arguments.input)
    policy = PhysicalMatrixPolicy(
        required_hosts=tuple(arguments.require_host or ("Windows", "Linux", "Darwin")),
        required_android_releases=tuple(arguments.require_android_release),
        minimum_manufacturer_families=arguments.minimum_manufacturers,
    )
    sealed = build_physical_matrix(records, policy)
    destination = arguments.output.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.partial")
    temporary.write_text(
        json.dumps(sealed.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    print(f"Physical matrix outcome: {sealed.report.outcome.value}")
    print(f"Accepted system records: {sealed.report.coverage.accepted_system_records}")
    print(f"Matrix SHA-256: {sealed.canonical_sha256}")
    for gap in sealed.report.gaps:
        print(f"GAP: {gap}")
    print(f"Written: {destination}")
    return 0 if sealed.report.outcome.value == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
