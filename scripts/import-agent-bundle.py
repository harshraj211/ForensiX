"""Verify and import a user-exported ForensiX agent bundle without ADB."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "forensic" / "src"))

from forensix_forensic.extractors.agent_apk import import_agent_bundle


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="User-exported .fxz bundle")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = import_agent_bundle(
        args.bundle, case_id=args.case_id, output_dir=args.output_dir
    )
    print(f"Imported {result.extraction_id} into {result.output_dir}")
    print(f"Collection complete: {result.success}")
    print(
        f"Contacts: {len(result.contacts)}; SMS: {len(result.sms_messages)}; "
        f"calls: {len(result.call_logs)}; visible apps: {len(result.installed_apps)}"
    )


if __name__ == "__main__":
    main()
