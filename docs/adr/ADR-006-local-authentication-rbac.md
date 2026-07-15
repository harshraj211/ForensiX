# ADR-006: Offline local authentication and explicit RBAC

- **Status:** Accepted
- **Date:** 15 July 2026

## Context

ForensiX must work offline on an investigator workstation while preventing unauthenticated access to connected devices, case data, evidence, reports, custody history, and administration. Long-lived bearer tokens in browser storage and cloud-only identity are unsuitable for the MVP.

## Decision

The first application run permits exactly one administrator bootstrap through the local API. Passwords are hashed with Argon2id using bounded input rules and are never logged or returned. Login applies a configurable failure threshold and timed lockout while using a dummy Argon2 verification for unknown usernames to reduce timing differences.

Sessions use random opaque tokens. SQLite stores only SHA-256 token hashes and a separate CSRF-token hash. The browser receives an HttpOnly, SameSite-strict session cookie and a separate SameSite-strict CSRF cookie; modifying API requests must provide the matching CSRF header. Login, refresh, logout, failures, and bootstrap create append-oriented authentication events with hashed usernames.

Authorization maps five stable roles—administrator, investigator, analyst, supervisor, and reviewer—to explicit permissions. API dependencies check permissions rather than hard-coded role names. Roles are reloaded for every authenticated request so disabling a user or changing a role takes effect immediately.

## Consequences

- No access or refresh token is stored in browser localStorage.
- Device detection and assessment now require authentication, CSRF validation, and `devices:operate`.
- Session rotation revokes the prior token; logout revokes the database session and clears cookies.
- The API remains loopback-only. Secure-cookie mode requires a TLS-capable packaged deployment before it is enabled.
- Case-level object authorization, password reset, user management, and audit-chain integration remain subsequent slices.
