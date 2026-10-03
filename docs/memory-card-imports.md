# Memory-card image examination

The Evidence Twin backup intake accepts `.img`, `.dd`, and `.raw` images up to
2 GiB. It seals the supplied bytes, creates a verified working copy, and runs
the `memory_card.fat32.image` parser automatically when the image contains a
supported FAT32 volume. The parser reads the image without mounting it.

## Implemented FAT32 scope

- FAT32 volume at sector zero or in one of four primary MBR partitions with a
  FAT32 partition type (`0x0B`, `0x0C`, `0x1B`, `0x1C`).
- Directory traversal to depth 16 and 25,000 entries, including valid VFAT
  long names and short-name fallback. Each directory entry retains its byte
  offset and raw DOS modified-date/time fields.
- SHA-256 of readable active files up to 512 MiB. A size limit, invalid chain,
  or truncated content produces a partial file record and an issue in the
  volume summary rather than a fabricated hash. An indexed active file can be
  downloaded from the verified working copy, including non-contiguous FAT
  chains, after its content hash is checked again.
- Deleted directory entries. When a deleted regular file's original first
  cluster and length survive, the parser tests a contiguous cluster range.
  It records a candidate SHA-256 only when all clusters are unallocated.
  The source record remains `deleted`; the content is a **candidate**, since
  deletion can erase the original cluster chain and later writes can reuse
  free space.
- The Evidence Twin artifact card offers a download for candidates. The API
  verifies the working-copy SHA-256, checks the FAT allocation state again,
  and recomputes the candidate hash before streaming the exact recorded byte
  length. Download headers include the candidate SHA-256.

The parser caps aggregate content hashing at 2 GiB per run in addition to
the 512 MiB per-file cap. Files past the cap remain visible with an explicit
hash status.

## Known limits

exFAT, FAT12/16, GPT-contained FAT32, ext4, and f2fs are not traversed by this
parser. Encrypted card images are not decrypted. Fragmented deleted files
cannot be reconstructed from a deleted FAT32 entry alone; a contiguous
candidate is not proof of original file identity. Images above 2 GiB are
rejected by the current HTTP import limit. The tests use synthetic FAT32
images; physical cards and vendor images require separate validation.

The FAT32 layout and directory-entry rules follow the Microsoft
[FAT driver sample](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/fastfat/fat.h).
