# ADR-010: Durable Acquisition-Job Preparation and Progress History

- Status: Accepted
- Date: 16 July 2026

## Context

An immutable plan records approved intent but cannot by itself represent execution state, cancellation, interruption, or recovery. Browser state is not authoritative and must not be trusted to report progress. ForensiX therefore needs a durable bridge between the reviewed plan and the future bounded executor without prematurely enabling ADB collection.

## Decision

ForensiX creates at most one durable acquisition job for each immutable plan. The job has restrictive references to its case, plan, and preparing operator. Preparation is idempotent, requires case access and the acquisition-operation permission, rejects closed cases and expired readiness, and moves the job through created and validating to ready.

Every job mutation appends a monotonically sequenced event containing the resulting state, progress, safe step/module labels, and the current bounded checkpoint. Checkpoints use canonical JSON and are limited to 8 KiB. Optimistic job versions detect stale writers; the versioned parent is flushed before inserting its event so concurrency failures cannot create a false duplicate sequence.

Cancellation is idempotent. A not-yet-running ready job cancels immediately. Active future jobs will enter cancelling and stop cooperatively at a safe checkpoint. On backend startup, active jobs become interrupted with a stable error code and an append-only interruption event; ready jobs remain ready.

The current preparation endpoint does not start a worker or executor. Its API and UI explicitly return `executor_available: false` and show the job as not running. No ADB command, file inventory, evidence pull, or evidence write occurs during preparation.

## Alternatives considered

- Keep progress only in memory or the browser: loses state on refresh/restart and is not reconstructable.
- Mutate one job row without events: compact, but hides transition history and makes recovery review difficult.
- Create multiple attempts for one plan immediately: supports retries, but weakens idempotency and is unnecessary before execution attempts exist.
- Use Celery or a broker: adds distributed infrastructure without value for the single-workstation MVP.

## Consequences

- The future executor consumes a durable ready job rather than browser input.
- A new immutable plan is required after readiness expires; an already prepared job preserves its original record.
- UI refreshes can reconstruct current state and event count from SQLite.
- Execution-attempt history may later require a separate attempt table if one plan can be retried more than once.
- SSE remains a future delivery optimization; persisted events are already authoritative.

## Security and forensic implications

- The browser cannot write progress, checkpoints, states, event sequence numbers, commands, or paths.
- Foreign keys prevent silent deletion of case, plan, operator, job, or event history.
- Checkpoint size and canonical serialization prevent unbounded or non-deterministic job metadata.
- Append-only events in local SQLite are reconstructable but not tamper-proof; the chained audit log remains required.
- A ready job proves only reviewed intent and durable preparation, not device revalidation, execution, completeness, or acquisition success.
