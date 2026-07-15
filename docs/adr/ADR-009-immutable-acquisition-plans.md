# ADR-009: Immutable Capability-Gated Acquisition Plans

- Status: Accepted
- Date: 15 July 2026

## Context

ForensiX must not convert a UI selection directly into ADB commands. Device capabilities vary by authorization state, Android version, access level, and storage visibility, while a readiness result can become stale after the device disconnects or changes state. The operator must also explicitly accept the documented limitations of controlled logical triage before an acquisition can be prepared.

## Decision

ForensiX persists an immutable acquisition plan before any execution begins. Each plan is bound to one case, case device, operator, and exact readiness assessment. Planning is allowed only for active cases, authorized case members with the acquisition permission, acknowledged limitations, and readiness snapshots no older than 30 minutes.

The service owns the registered module catalog and preset scopes. The browser may select only known scopes and modules; the backend independently verifies every module against the stored capability snapshot. Custom plans use the same catalog and capability rules. Unsupported, blocked, stale, cross-case, and empty selections are rejected.

The readiness snapshot and complete canonical plan payload receive separate SHA-256 hashes. The plan hash covers the case, device, assessment, operator, scope, ordered modules, acknowledged limitation text, schema version, readiness timestamps, and snapshot hash. Plans have no update or delete endpoint. Creation appends a case event.

Creating a plan does not start a durable job, execute ADB, enumerate files, or acquire evidence. Execution will be a later transition that first revalidates the live device and records progress independently.

## Alternatives considered

- Start acquisition directly from the browser request: fewer steps, but loses an auditable frozen intent and increases command-injection and stale-state risk.
- Store only a scope name: cannot reproduce the exact module selection when presets or plugins change.
- Always use the latest readiness result: hides which capability decision authorized the plan and makes later review ambiguous.
- Allow mutable draft plans: convenient editing, but weakens provenance; creating a new plan is clearer and preserves history.

## Consequences

- Operators must reassess a device when readiness is older than 30 minutes.
- Preset changes do not alter existing plans because resolved modules are stored with the plan.
- Execution can consume a stable, reviewable input without trusting browser state.
- A new plan is required to change scope, modules, or acknowledgement.
- The future executor must still revalidate authorization, device identity, capabilities, disk space, and freshness immediately before running.

## Security and forensic implications

- No arbitrary command, shell text, or filesystem path is accepted by the planning API.
- Object-level case authorization and explicit acquisition permission are enforced server-side.
- Canonical hashes make accidental or later modification detectable when verified, but a hash stored in the same local SQLite database is not tamper-proof.
- The planned chained audit log and signed/exported manifests remain necessary for stronger tamper evidence.
- A plan describes intended controlled logical operations; it is not proof that acquisition occurred or that evidence is complete.
