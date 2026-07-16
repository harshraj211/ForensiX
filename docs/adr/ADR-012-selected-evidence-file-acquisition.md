# ADR-012: Selected Evidence-File Acquisition

**Status:** Accepted
**Date:** 16 July 2026

## Context

The bounded inventory produces device-controlled relative filenames. Those names are hostile input and must not be accepted from the browser or interpolated into an Android shell command. File transfer can also exhaust workstation storage or leave ambiguous partial results.

## Decision

The acquisition API accepts only an opaque persisted inventory-item ID. The backend verifies case access, open case state, completed inventory ownership, item membership, device identity, authorization, build fingerprint, root readability, and at least 200 MiB of free storage.

The ADB policy reconstructs the remote path from the approved root and persisted relative path. It executes `adb pull` as a shell-free argument vector. Each selected transfer is limited to 100 MiB and 120 seconds. The subprocess writes to a random partial path inside a permission-restricted evidence root. Oversized partials are deleted; other interrupted partials are preserved and explicitly flagged.

Successful bytes are sealed without overwrite, streamed through SHA-256, and linked to a durable provenance record. A canonical JSON manifest records the full case, plan, device, inventory, source path, storage key, timestamps, tool version, size, and file SHA-256; the manifest is itself hashed. Physical storage keys are deliberately short for Windows path compatibility while full identifiers remain in SQLite and the manifest.

Every result is labeled `not_physically_validated` until the controlled device matrix is executed.

## Alternatives

- Browser-supplied remote paths were rejected because they break the command-policy and provenance boundary.
- `adb shell cat` and per-file shell metadata commands were rejected because ADB shell argument serialization makes hostile-filename handling unsafe.
- Bulk recursive pulls were deferred because they weaken per-item selection, size enforcement, restart recovery, and reviewability.

## Consequences

The current implementation supports deliberate one-file-at-a-time collection from shared storage. It does not access private app sandboxes, guarantee completeness, resume partial transfers, or establish forensic validation. Physical-device validation, explicit re-verification records, audit-chain integration, and custody events remain release gates.
