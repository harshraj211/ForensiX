# ADR-005: Durable local job state machine

- **Status:** Accepted
- **Date:** 15 July 2026

## Context

Acquisition, hashing, parsing, indexing, timeline, report, and export operations can outlive a browser request and can be interrupted by device disconnects or backend restarts. FastAPI in-memory background tasks cannot provide the required durable state or recovery semantics.

## Decision

The MVP uses a SQLite-backed local job model with explicit job types and a validated state-transition graph. Job records contain progress, current step/module, cancellation intent, resume capability, result/error references, timestamps, and a SQLAlchemy version counter for stale-update detection.

Progress is monotonic and only mutable in active states. Cancellation is immediate before execution and cooperative while active. On backend startup, jobs that were validating, running, cancelling, or verifying are marked `interrupted` with a stable restart error instead of being falsely reported as running or failed.

## Consequences

- Browser refreshes do not erase job state.
- Concurrent stale writers fail rather than silently overwriting newer job state.
- The execution runner and SSE projection can be added without changing the state vocabulary.
- Byte-level resume is not promised; each job and acquisition module must explicitly declare whether its checkpoint is safe to resume.
- SQLite remains appropriate for one workstation; a future queue can consume the same durable state contract.
