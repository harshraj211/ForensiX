# Deleted-data research boundary

ForensiX does not promise deleted-data recovery from an ordinary Android Debug Bridge connection.
Modern Android file-based encryption, application sandboxes, TRIM, flash translation layers, and
the lack of block-device access make a generic non-rooted recovery claim technically indefensible.

## Implemented experimental assessment

An examiner can run a metadata-only recovery-readiness assessment against a hash-verified Evidence
Twin working copy. The bounded probe recognizes:

- SQLite database headers and their declared freelist page count.
- SQLite WAL headers, complete frame count, and trailing-byte condition.
- SQLite rollback-journal headers and declared page-record metadata.
- Supported SQLite members extracted from ZIP or TAR containers under archive member, size, and
  path-depth limits.

The result is stored once per working copy with its tool version, examiner, source inspection,
candidate counts, limitations, canonical SHA-256, and a hash-chained audit event. Repeating the
operation returns the same immutable record.

## What the assessment does not do

- It does not carve SQLite cells or emit recovered artifacts.
- It does not infer that a freelist page, WAL frame, or journal page contains deleted user data.
- It does not reconstruct committed or uncommitted transactions.
- It does not bypass Android encryption, application authentication, or device locks.
- It does not provide block-level access or a bit-for-bit Android device image.
- It does not classify any normalized artifact as `deleted` or `recovered`.

The UI therefore uses the term **candidate region** and always displays the warning that candidate
regions are not recovered records or proof of deletion.

## Promotion gates

Row-level recovery remains research-only until each parser has a versioned known-answer corpus,
repeatability results, false-positive and false-negative measurements, schema/version coverage,
corruption handling, examiner-review workflow, and an approved forensic validation report.

The maturity path is:

1. `not_available`
2. `experimental`
3. `controlled_dataset_validated`
4. `rooted_device_validated`
5. `production_validated`

The current implementation is `experimental`. It may identify that further examination is worth
performing on a lawfully obtained database or image, but it is not itself deleted-data recovery.
