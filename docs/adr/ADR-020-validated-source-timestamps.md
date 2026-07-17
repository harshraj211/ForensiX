# ADR-020: Validated shared-storage source timestamps

## Status

Accepted - 17 July 2026

## Context

The original timeline contained only the workstation acquisition timestamp. Android shared storage can expose a file modification epoch and size, but the device clock can be wrong, filesystem metadata can change, and filenames are hostile input. ForensiX must preserve useful source claims without inventing creation/access times or interpolating a timezone.

## Decision

- Replace the bounded path-only inventory operation with one fixed `find -exec stat` operation under the internally approved shared-storage root.
- The command format is fixed in policy and reports path, byte size, and Unix modification epoch. No browser value becomes a shell command or remote path argument.
- Parse records from the right so colons in filenames remain valid; reject control-character paths, malformed numbers, negative sizes, out-of-range epochs, duplicates, escaped roots, excessive depth, and excess items.
- Preserve the original epoch string, normalized UTC value, source identifier, second precision, and `medium` confidence in the inventory manifest and normalized artifact metadata.
- Keep the workstation collection timestamp as a separate high-confidence event. Create `source_file_modified_at` only when the stat claim validates.
- Label the timezone basis as UTC derived from a Unix epoch reported by Android stat. Explicitly disclose that the device clock and filesystem metadata were not independently validated.
- Preserve both inventory size and acquired size and report whether they match; never rewrite an earlier source claim after transfer.
- Downgrade a source timeline event to low confidence and add an explicit clock-skew warning when its reported time is after workstation collection.

## Consequences

The timeline can now distinguish an Android-reported modification claim from the workstation collection event. Existing inventory rows migrate with no source timestamp and therefore do not gain invented events. The fixed operation depends on Android's `find` and `stat` implementation and still requires validation across supported Android/OEM versions. A malformed stat record is skipped rather than downgraded into a path-only assertion.

## Alternatives

- Running a separate `stat` command for each filename was rejected because hostile device filenames would have to re-enter remote-shell argument construction and up to 250 extra commands would be required.
- Treating modification time as a creation or access time was rejected because Android stat does not justify those claims here.
- Assigning high confidence was rejected because the device clock, user changes, sync tools, and filesystem behavior remain outside workstation control.

## Validation

Known-answer tests cover colon-containing paths, exact epoch conversion, malformed and out-of-range records, fixed command arguments, manifest determinism, database migration, size consistency, artifact provenance, two distinct timeline claims, API fields, and mock end-to-end acquisition.
