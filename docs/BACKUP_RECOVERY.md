# Encrypted backup and recovery

ForensiX backups are offline workstation snapshots. They contain a consistent SQLite backup and
all sealed files below `data/evidence`. They do not modify source evidence or Android devices.

Create a backup while no acquisition or parser job is running:

```powershell
.\.venv\Scripts\python.exe .\scripts\forensix-backup.py create D:\ForensiX-Backups\casework.fxb
```

Verify it independently before moving or deleting any primary data:

```powershell
.\.venv\Scripts\python.exe .\scripts\forensix-backup.py verify D:\ForensiX-Backups\casework.fxb
```

Restore only into a new, empty directory:

```powershell
.\.venv\Scripts\python.exe .\scripts\forensix-backup.py restore D:\ForensiX-Backups\casework.fxb D:\ForensiX-Restore
```

The `FXBACK01` container uses scrypt with a random salt to derive an AES-256-GCM key. Each 1 MiB
chunk has independent authentication and a unique nonce; the authenticated header records the
plaintext size and SHA-256. The decrypted ZIP payload has a bounded manifest containing every file
size and SHA-256, and restore re-verifies each member before sealing it. Incorrect passwords,
modified chunks, unsafe paths, duplicate members, manifest mismatch, and non-empty restore targets
are rejected.

The passphrase is never written by the utility. Losing it makes the backup unrecoverable. Store it
in an agency-approved password manager or escrow process, never beside the backup. This container
protects backup copies; production workstations still require BitLocker, FileVault, or LUKS for
live database/evidence encryption at rest. Stop active work and investigate any verification
failure rather than repeatedly attempting restore.
