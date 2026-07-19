"""Offline CLI for creating, verifying, and restoring encrypted ForensiX backups."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from forensix_server.backup import (
    BackupError,
    create_backup,
    prompt_passphrase,
    restore_backup,
    verify_backup,
)
from forensix_server.config import Settings
from forensix_server.db import Database


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("output", type=Path)
    create.add_argument("--overwrite", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("backup", type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "create":
            settings = Settings()
            database = Database(settings.resolved_database_url, settings.resolved_data_dir)
            try:
                result = create_backup(
                    database,
                    arguments.output,
                    prompt_passphrase(confirmation=True),
                    overwrite=arguments.overwrite,
                )
            finally:
                database.dispose()
        elif arguments.command == "verify":
            result = verify_backup(arguments.backup, prompt_passphrase(confirmation=False))
        else:
            result = restore_backup(
                arguments.backup,
                arguments.destination,
                prompt_passphrase(confirmation=False),
            )
    except BackupError as error:
        parser.exit(1, f"Backup operation failed: {error}\n")
    print(json.dumps(asdict(result), default=str, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
