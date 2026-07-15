# ADR-001: Monorepo

- Status: Accepted
- Date: 2026-07-15

## Decision

Use one repository with a pnpm workspace for the React application and independently packaged Python projects for the API, application services, and forensic engine. Enforce one-way dependencies: API -> server/forensic ports; server -> forensic ports; forensic imports neither FastAPI nor SQLAlchemy.

## Consequences

Contracts and changes are reviewed together, while forensic code remains independently testable. Python packages are installed editable during development and can be split later without changing their public interfaces.
