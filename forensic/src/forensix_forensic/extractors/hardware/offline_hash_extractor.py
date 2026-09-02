"""Android offline lock-screen hash extractor.

Pulls password-equivalent data from a rooted device so the examiner can
perform offline hash cracking with hashcat or John the Ripper:

* Reads ``/data/system/locksettings.db`` for:
  - ``lockscreen.password_salt`` (legacy FDE salt)
  - ``lockscreen.passwordHistory``
  - Pattern-hash path (``/data/system/gesture.key`` or ``pattern.key``)
* Reads ``/data/misc/gatekeeper/`` for Gatekeeper enrolled-password blobs
* Reads synthetic-password blobs from ``/data/system_de/0/spblob/``
* Packages everything into a ``HashDump`` frozen dataclass
* SHA-256 seals every extracted blob
* Full structured timeline logging
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient


@dataclass(frozen=True, slots=True)
class GatekeeperBlob:
    """Raw Gatekeeper enrolled password blob from /data/misc/gatekeeper/."""

    user_id: int
    filename: str
    raw_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class SpblobFile:
    """Synthetic password blob file from /data/system_de/0/spblob/."""

    filename: str
    raw_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class HashDump:
    """Container for extracted lockscreen hashes and credential blobs."""

    dump_id: str
    device_serial: str
    case_id: str
    lock_type: str
    gatekeeper_blobs: tuple[GatekeeperBlob, ...]
    spblob_files: tuple[SpblobFile, ...]
    pattern_hash: bytes | None
    password_salt: str | None
    aggregate_sha256: str
    timeline: list[dict[str, str]]
    dumped_at: str
    error_message: str | None
    success: bool


class OfflineHashExtractor:
    """Extracts Android credential hashes from rooted devices for offline cracking."""

    def __init__(self, adb: AdbClient, output_dir: Path) -> None:
        self._adb = adb
        self._output_dir = output_dir
        self._timeline: list[dict[str, str]] = []

    async def extract(self, serial: str, case_id: str, operator_id: str) -> HashDump:
        """Run extraction of locksettings, Gatekeeper blobs, and synthetic password blobs."""
        dump_id = str(uuid4())
        dumped_at = datetime.now(UTC).isoformat()
        self._log(
            "extract_start",
            {
                "dump_id": dump_id,
                "serial": serial,
                "case_id": case_id,
                "operator_id": operator_id,
            },
        )

        self._output_dir.mkdir(parents=True, exist_ok=True)
        gk_blobs: list[GatekeeperBlob] = []
        sp_files: list[SpblobFile] = []
        pattern_bytes: bytes | None = None
        salt_val: str | None = None
        error_msg: str | None = None

        try:
            # 1. Read locksettings.db keys
            settings = await self._read_locksettings(serial)
            salt_val = settings.get("lockscreen.password_salt")
            lock_type = settings.get("lockscreen.password_type", "unknown")

            # 2. Pull Gatekeeper blobs
            gk_blobs = await self._pull_gatekeeper_blobs(serial)

            # 3. Pull Synthetic Password blobs
            sp_files = await self._pull_spblobs(serial)

            # 4. Pull Gesture / Pattern key if available
            pattern_bytes = await self._pull_pattern_key(serial)

            success = True
        except Exception as exc:  # noqa: BLE001
            error_msg = str(exc)
            lock_type = "unknown"
            success = False

        agg_hash = self._aggregate_hash(gk_blobs, sp_files, pattern_bytes)

        self._log(
            "extract_complete",
            {
                "success": str(success),
                "gatekeeper_count": str(len(gk_blobs)),
                "spblob_count": str(len(sp_files)),
                "has_pattern": str(pattern_bytes is not None),
            },
        )

        return HashDump(
            dump_id=dump_id,
            device_serial=serial,
            case_id=case_id,
            lock_type=lock_type,
            gatekeeper_blobs=tuple(gk_blobs),
            spblob_files=tuple(sp_files),
            pattern_hash=pattern_bytes,
            password_salt=salt_val,
            aggregate_sha256=agg_hash,
            timeline=list(self._timeline),
            dumped_at=dumped_at,
            error_message=error_msg,
            success=success,
        )

    async def _read_locksettings(self, serial: str) -> dict[str, str]:
        settings: dict[str, str] = {}
        try:
            cmd = (
                'su -c "sqlite3 /data/system/locksettings.db '  # noqa: S608
                "'SELECT name,value FROM locksettings;'\""
            )
            output = await self._adb.shell(serial, cmd)  # type: ignore[attr-defined]
            for line in output.splitlines():
                if "|" in line:
                    k, _, v = line.partition("|")
                    settings[k.strip()] = v.strip()
        except Exception as exc:  # noqa: BLE001
            self._log("read_locksettings_failed", {"error": str(exc)})
        return settings

    async def _pull_gatekeeper_blobs(self, serial: str) -> list[GatekeeperBlob]:
        blobs: list[GatekeeperBlob] = []
        try:
            ls_cmd = "su -c 'ls /data/misc/gatekeeper/'"
            ls_out = await self._adb.shell(serial, ls_cmd)  # type: ignore[attr-defined]
            filenames = [f.strip() for f in ls_out.splitlines() if f.strip() and "No such" not in f]
            for fn in filenames:
                remote_path = f"/data/misc/gatekeeper/{fn}"
                local_path = self._output_dir / f"gatekeeper_{fn}"
                try:
                    await self._adb.pull(serial, remote_path, str(local_path))  # type: ignore[attr-defined]
                    if local_path.exists():
                        data = local_path.read_bytes()
                        sha = hashlib.sha256(data).hexdigest()
                        user_id = 0
                        if "_" in fn:
                            try:
                                user_id = int(fn.split("_")[0])
                            except ValueError:
                                user_id = 0
                        blob = GatekeeperBlob(
                            user_id=user_id, filename=fn, raw_bytes=data, sha256=sha
                        )
                        blobs.append(blob)
                except Exception:  # noqa: BLE001, S112
                    continue
        except Exception as exc:  # noqa: BLE001
            self._log("pull_gatekeeper_failed", {"error": str(exc)})
        return blobs

    async def _pull_spblobs(self, serial: str) -> list[SpblobFile]:
        files: list[SpblobFile] = []
        try:
            ls_cmd = "su -c 'ls /data/system_de/0/spblob/'"
            ls_out = await self._adb.shell(serial, ls_cmd)  # type: ignore[attr-defined]
            filenames = [f.strip() for f in ls_out.splitlines() if f.strip() and "No such" not in f]
            for fn in filenames:
                remote_path = f"/data/system_de/0/spblob/{fn}"
                local_path = self._output_dir / f"spblob_{fn}"
                try:
                    await self._adb.pull(serial, remote_path, str(local_path))  # type: ignore[attr-defined]
                    if local_path.exists():
                        data = local_path.read_bytes()
                        sha = hashlib.sha256(data).hexdigest()
                        files.append(SpblobFile(filename=fn, raw_bytes=data, sha256=sha))
                except Exception:  # noqa: BLE001, S112
                    continue
        except Exception as exc:  # noqa: BLE001
            self._log("pull_spblobs_failed", {"error": str(exc)})
        return files

    async def _pull_pattern_key(self, serial: str) -> bytes | None:
        for remote_path in ["/data/system/gesture.key", "/data/system/pattern.key"]:
            local_path = self._output_dir / Path(remote_path).name
            try:
                await self._adb.pull(serial, remote_path, str(local_path))  # type: ignore[attr-defined]
                if local_path.exists() and local_path.stat().st_size > 0:
                    return local_path.read_bytes()
            except Exception:  # noqa: BLE001, S112
                continue
        return None

    def _aggregate_hash(
        self,
        gk_blobs: list[GatekeeperBlob],
        sp_files: list[SpblobFile],
        pattern_bytes: bytes | None,
    ) -> str:
        h = hashlib.sha256()
        for b in sorted(gk_blobs, key=lambda x: x.filename):
            h.update(f"gatekeeper:{b.filename}:{b.sha256}\n".encode())
        for f in sorted(sp_files, key=lambda x: x.filename):
            h.update(f"spblob:{f.filename}:{f.sha256}\n".encode())
        if pattern_bytes:
            h.update(f"pattern:{hashlib.sha256(pattern_bytes).hexdigest()}\n".encode())
        return h.hexdigest()

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "event": event,
                **details,
            }
        )
