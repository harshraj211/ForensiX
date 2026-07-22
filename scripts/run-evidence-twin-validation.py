"""Run the isolated Evidence Twin known-answer validation workflow."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from forensix_server.validation import run_evidence_twin_validation


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    with TemporaryDirectory(prefix="forensix-evidence-twin-validation-") as temporary:
        sealed = run_evidence_twin_validation(Path(temporary))
    destination = arguments.output.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = destination.with_name(f".{destination.name}.partial")
    temporary_output.write_text(
        json.dumps(sealed.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_output.replace(destination)
    print(f"Validation outcome: {sealed.report.outcome.value}")
    print(f"Report SHA-256: {sealed.canonical_sha256}")
    print(f"Written: {destination}")
    return 0 if sealed.report.outcome.value.startswith("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
