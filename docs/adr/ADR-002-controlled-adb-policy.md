# ADR-002: Controlled ADB Operation Policy

- Status: Accepted
- Date: 2026-07-15

## Decision

No public interface accepts arbitrary shell text. All ADB activity is represented by typed operations, serial-scoped arguments, bounded execution, and structured results. The MVP labels its workflow Controlled Logical Triage Mode and records potential side effects.

## Consequences

New ADB capabilities require a reviewed operation implementation and tests. This limits flexibility intentionally and prevents the web client from becoming a command-execution surface.
