# ADR-003: Local Modular Monolith

- Status: Accepted
- Date: 2026-07-15

## Decision

Run a localhost-only FastAPI modular monolith with SQLite and filesystem evidence storage. The browser UI communicates through versioned REST endpoints. Distributed queues and cloud dependencies are excluded from the MVP.

## Consequences

Deployment and offline recovery remain understandable for a single workstation. Durable jobs and future database migration must be hidden behind explicit ports so deployment can evolve without rewriting forensic modules.
