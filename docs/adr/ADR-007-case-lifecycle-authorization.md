# ADR-007: Case lifecycle and object-level authorization

- **Status:** Accepted
- **Date:** 15 July 2026

## Context

Every device, acquisition, artifact, report, custody event, and audit record must eventually belong to a case. Global role permissions alone are insufficient because an analyst or investigator must not gain access to every case merely by holding a system role.

## Decision

Cases receive an opaque UUID and a human-readable unique number. Creation assigns the creator as an owner and appends a `case_created` event. Case membership is explicit and uses owner, investigator, analyst, supervisor, or reviewer access levels. Administrators can inspect all local cases; other users require both the relevant system permission and membership in the target case.

The lifecycle is `open -> active -> closed -> archived`, with direct `open -> closed` permitted. Closed cases may be reopened or archived only by an administrator or supervisor. Archived cases are terminal. Closed and archived case metadata cannot be edited.

Case rows use SQLAlchemy version counters. Modifying requests supply the expected version and receive a conflict rather than silently overwriting a concurrent update. Case creation, metadata changes, lifecycle transitions, and membership changes append separate case events. No case-delete or event-update endpoint exists.

## Consequences

- Backend services enforce object access independently of the React navigation.
- A system role does not automatically reveal non-member cases, except for the explicit administrator oversight policy.
- Future device and acquisition records can use restrictive case foreign keys.
- Custody and tamper-evident audit events remain separate append-only ledgers but can reference the same case lifecycle events.
- User-management UI is still required before administrators can assign additional real users through the application.
