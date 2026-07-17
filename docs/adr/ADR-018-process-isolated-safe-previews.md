# ADR-018: Generate safe previews as bounded process-isolated derivatives

## Status

Accepted for the development MVP on 17 July 2026.

## Context

Acquired files are hostile input. Rendering a sealed source file in the browser or decoding it
inside the API process would expose the investigator session and the evidence service to parser
defects, active content, decompression bombs, and MIME confusion. Filename extensions are not a
trustworthy content-type signal. At the same time, analysts need a narrowly scoped image preview
that never changes the source evidence object.

## Decision

ForensiX creates at most one append-only preview outcome per artifact. Before decoding, the parent
re-hashes the sealed source and compares it with the acquisition hash. It then launches a standalone
Python worker in isolated mode with fixed arguments, no shell, an eight-second deadline, a 25 MiB
input ceiling, a 40-megapixel ceiling, a 5 MiB output ceiling, and POSIX address-space/CPU/file limits
where supported. The worker recognizes bounded magic bytes and accepts only JPEG, PNG, GIF, and
WebP. It decodes only the first image frame, resizes to at most 1024 pixels per edge, strips source
metadata by conversion, and writes a new PNG into a contained derivative path.

The parent atomically seals and hashes the PNG. The API authorizes every status, generation, and
content request against the case. It serves only the derivative with `image/png`, `nosniff`, a
sandboxed content-security policy, same-origin resource policy, and no-store caching. Rejections,
failures, signature/extension mismatch, limits, worker version, derivative hash, and actor are
persisted and audited. Original artifact fields and evidence bytes remain unchanged.

SVG, PDF, Office, archive, executable, audio, and video content is never rendered by this worker.

## Alternatives considered

- Rendering raw evidence in the browser was rejected because active content and browser parsers
  would operate in the authenticated application origin.
- Decoding images inside FastAPI was rejected because a parser crash or memory exhaustion could
  take down acquisition and case services.
- Relying on extension or HTTP MIME labels was rejected because they are attacker-controlled.
- Describing the worker as a complete sandbox was rejected. Windows process isolation plus a parent
  timeout is not equivalent to an AppContainer, restricted token, VM, or disposable container.

## Consequences and limitations

The output is a convenience derivative, not source evidence. Its SHA-256 and provenance are retained
so it can be verified independently. A failed or rejected artifact is not retried automatically,
which prevents repeated hostile parsing; a future versioned reprocessing workflow must create a new
derivation attempt rather than overwrite history.

The current Windows implementation is process-isolated and bounded but not an absolute OS sandbox.
Production packaging should add Windows Job Objects/restricted tokens, macOS sandbox profiles, and
Linux seccomp/namespaces where available. Pillow and each enabled decoder remain security-sensitive
dependencies and require patching, hostile-corpus regression tests, and release scanning.
