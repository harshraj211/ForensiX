# ADR-008: Case-Linked Device Identity and Readiness History

- Status: Accepted
- Date: 15 July 2026

## Context

Transport enumeration is useful before evidence collection, but an acquisition must not rely on an unscoped browser state or an unrecorded capability decision. Android serials are also sensitive identifiers. ForensiX needs a stable way to recognize a reconnected device, keep every readiness result within an authorized case, preserve earlier assessments, and prevent operations against closed records.

## Decision

ForensiX stores a `case_devices` identity for every successfully assessed device and append-only `case_device_assessments` records for each readiness run. A separate append-only detection table records case-scoped ADB enumeration. Every write requires the global device-operation permission, case membership or administrator access, CSRF validation, and an open or active case.

The raw ADB serial is used only for the live, serial-scoped ADB operation. Persistence contains SHA-256 of the serial and a short masked suffix for recognition. Snapshot JSON explicitly excludes the serial. The device identity is unique by case and serial hash, so repeated assessments extend history rather than create ambiguous duplicate devices.

Closed and archived cases remain readable but reject new detection and assessment records. Case events record each run and assessment. No update or delete endpoint is provided for readiness snapshots.

## Alternatives considered

- Store raw serials in SQLite: simpler reconnect UX, but unnecessarily increases sensitive identifier exposure before encryption-at-rest support exists.
- Keep readiness only in the browser: loses provenance, cannot support acquisition planning, and allows stale capability promises.
- Overwrite the latest snapshot: hides historical device state and parser/tool-version changes.
- Treat a device as globally shared across cases: creates cross-case disclosure and authorization ambiguity.

## Consequences

- A live transport must be matched by hashing its current serial before acquisition.
- The UI can show masked recognition data but not recover the original serial from persistence.
- Repeated assessments preserve history and tool version context.
- Acquisition plans can bind to a stable case-device ID and a specific readiness snapshot.
- Full serial reporting will require a separately designed encrypted evidence-metadata policy if later required.

## Security and forensic implications

- Object-level authorization is checked before any case-scoped ADB command executes.
- Raw serials are excluded from readiness JSON and database records.
- Foreign keys use restrictive deletion; case evidence history is not cascade-deleted.
- Append-only records are not tamper-proof. The planned chained audit log is still required for tamper evidence.
- A readiness snapshot is point-in-time information and must be revalidated immediately before acquisition.
