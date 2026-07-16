# ADR-011: Bounded Shared-Storage Path Inventory

**Status:** Accepted  
**Date:** 16 July 2026

## Context

ForensiX needs a first real acquisition operation that is useful on modern authorized, non-rooted Android devices without implying private-app access or evidence completeness. Android filenames are hostile input. Passing a discovered filename into a later `adb shell` command would create quoting and command-injection risk.

## Decision

The first executor performs one internally defined, serial-scoped `find` operation against one root approved by the immutable readiness snapshot. Immediately before execution it revalidates transport authorization, hashed device identity, build fingerprint, root readability, case state, plan scope, and workstation free space.

The operation is capped at depth 6, 250 persisted relative paths, 30 seconds, and the ADB runner's 1 MiB output limit. It stores only normalized relative paths, extensions, per-path SHA-256 values, counts, limits, and a canonical manifest SHA-256. It does not read or pull Android file contents and does not issue per-file shell commands.

Durable job checkpoints record validation, execution, persistence, cancellation, completion, and safe failure codes. Partial metadata already returned by an operation that receives a concurrent cancellation request is preserved and the job finishes as cancelled.

## Alternatives

- Per-file `stat` commands were rejected because device-derived paths would have to cross a shell boundary.
- Recursive file pulling was deferred until real-device validation, evidence manifests, verification records, and custody/audit controls exist.
- Arbitrary roots or commands supplied by the browser remain prohibited.

## Consequences

The inventory is useful for triage navigation and extension counts but has no file size, timestamps, hashes of file contents, or completeness guarantee. App-private data remains inaccessible on ordinary non-rooted devices. A future metadata or pull design must preserve the fixed-policy boundary and treat all filenames and file contents as hostile.
