"""Create the fixed ForensiX known-file fixture for a controlled test device."""

import argparse
from pathlib import Path

from forensix_forensic.adb import KNOWN_FILE_SHA256, write_known_file_fixture


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    destination = arguments.output.expanduser().resolve()
    write_known_file_fixture(destination)
    print(f"Fixture SHA-256: {KNOWN_FILE_SHA256}")
    print(f"Written without overwrite: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
