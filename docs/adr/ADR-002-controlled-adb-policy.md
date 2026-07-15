# ADR-002: Controlled ADB Operation Policy

- Status: Accepted
- Date: 2026-07-15

## Decision

No public interface accepts arbitrary shell text. All ADB activity is represented by typed operations, serial-scoped arguments, bounded execution, and structured results. The MVP labels its workflow Controlled Logical Triage Mode and records potential side effects.

The operation catalog is closed in code and currently permits only server version, transport enumeration, property retrieval, package listing, and fixed shared-storage predicates. Storage paths are internal enum values mapped to `/sdcard` and `/storage/emulated/0`; neither the API nor UI can submit a remote path. Root probing invokes only `test -d` and `test -r`, returns no file content or filenames, uses a five-second timeout per predicate, and treats exit codes outside the boolean `0`/`1` contract as command failures.

Android documents serial-scoped single shell commands and notes that many device commands are provided by Toybox. Android's Toybox `test` implementation defines both `-d` (directory) and `-r` (readable) predicates. These primary references establish the probe's command contract:

- [Android Debug Bridge documentation](https://developer.android.com/tools/adb)
- [Android Toybox `test` implementation](https://android.googlesource.com/platform/external/toybox/+/e59a3fc0e95e440a2b52d5b80248b21cbc4d3387/toys/posix/test.c)

## Consequences

New ADB capabilities require a reviewed operation implementation and tests. This limits flexibility intentionally and prevents the web client from becoming a command-execution surface.

A successful readability predicate is only a point-in-time capability signal. It does not prove that all descendants can be enumerated or acquired, does not bypass scoped storage or app sandboxes, and does not establish completeness. Metadata inventory and evidence pull remain separately gated operations.
