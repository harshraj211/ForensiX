"""Hashcat subprocess launcher for Android lock-screen hash cracking.

Supports the following hashcat modes for Android:

* Mode 13800 — Android FBE / Gatekeeper PIN/Password (synthetic password)
* Mode 18800 — Android FDE (PBKDF2-HMAC-SHA1 disk encryption)
* Mode 10    — MD5 (pattern.key legacy Android < 6)

This launcher does NOT bundle wordlists or hashcat itself; the examiner
must install hashcat and supply wordlist/rule paths via the config.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from uuid import uuid4


class HashcatMode(IntEnum):
    """Supported hashcat modes for Android hashes."""

    ANDROID_PATTERN_MD5 = 10
    ANDROID_GATEKEEPER = 13800
    ANDROID_FDE = 18800


@dataclass(frozen=True, slots=True)
class HashcatConfig:
    """Configuration options for executing Hashcat."""

    hashcat_binary: Path
    wordlist_path: Path | None = None
    rules_path: Path | None = None
    mask: str | None = None
    device_id: int = 0
    session_name: str = "forensix"
    extra_args: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HashcatJobResult:
    """Sealed result of a Hashcat cracking job."""

    job_id: str
    mode: int
    hash_file: str
    cracked_credentials: tuple[str, ...]
    potfile_path: str
    return_code: int
    stdout_tail: str
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool
    error_message: str | None


class HashcatLauncher:
    """Manages hashcat execution for offline lockscreen credential recovery."""

    def __init__(self, config: HashcatConfig, output_dir: Path) -> None:
        self._cfg = config
        self._output_dir = output_dir

    async def run(
        self,
        hash_file: Path,
        mode: HashcatMode,
        case_id: str,
        *,
        timeout_seconds: int = 3600,
    ) -> HashcatJobResult:
        """Run hashcat against a local hash file."""
        job_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()

        self._output_dir.mkdir(parents=True, exist_ok=True)
        potfile = self._output_dir / f"{job_id}.potfile"

        try:
            self._validate_hashcat_binary()
            cmd = self._build_command(hash_file, mode, potfile)

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            stdout_lines: list[str] = []

            async def read_stdout() -> None:
                if process.stdout:
                    while True:
                        line = await process.stdout.readline()
                        if not line:
                            break
                        text = line.decode(errors="replace").rstrip()
                        stdout_lines.append(text)
                        if len(stdout_lines) > 50:
                            stdout_lines.pop(0)

            try:
                await asyncio.wait_for(
                    asyncio.gather(process.wait(), read_stdout()),
                    timeout=float(timeout_seconds),
                )
            except TimeoutError:
                with suppress(ProcessLookupError):
                    process.kill()
                return self._error_result(
                    job_id=job_id,
                    mode=mode.value,
                    hash_file=str(hash_file),
                    potfile=str(potfile),
                    started_at=started_at,
                    t0=t0,
                    msg=f"Hashcat execution timed out after {timeout_seconds} seconds",
                    tail="\n".join(stdout_lines),
                )

            rc = process.returncode if process.returncode is not None else -1
            cracked = await self._read_potfile(potfile)
            finished_at = datetime.now(UTC).isoformat()
            duration = asyncio.get_event_loop().time() - t0

            # Hashcat returns 0 (cracked), 1 (exhausted), or 2 (aborted)
            success = rc in (0, 1) or len(cracked) > 0

            return HashcatJobResult(
                job_id=job_id,
                mode=mode.value,
                hash_file=str(hash_file),
                cracked_credentials=cracked,
                potfile_path=str(potfile),
                return_code=rc,
                stdout_tail="\n".join(stdout_lines[-20:]),
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=round(duration, 3),
                success=success,
                error_message=None if success else f"Hashcat exited with return code {rc}",
            )

        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                job_id=job_id,
                mode=mode.value,
                hash_file=str(hash_file),
                potfile=str(potfile),
                started_at=started_at,
                t0=t0,
                msg=str(exc),
                tail="",
            )

    def _validate_hashcat_binary(self) -> None:
        if not self._cfg.hashcat_binary.exists():
            raise FileNotFoundError(
                f"Hashcat binary not found at: {self._cfg.hashcat_binary}"
            )

    def _build_command(
        self, hash_file: Path, mode: HashcatMode, potfile: Path
    ) -> list[str]:
        cmd = [
            str(self._cfg.hashcat_binary),
            "-m",
            str(mode.value),
            "--potfile-path",
            str(potfile),
            "--session",
            self._cfg.session_name,
            "-d",
            str(self._cfg.device_id),
        ]

        if self._cfg.mask:
            cmd.extend(["-a", "3", str(hash_file), self._cfg.mask])
        elif self._cfg.wordlist_path:
            cmd.extend(["-a", "0", str(hash_file), str(self._cfg.wordlist_path)])
            if self._cfg.rules_path:
                cmd.extend(["-r", str(self._cfg.rules_path)])
        else:
            # Default fallback dict/mask if neither specified
            cmd.extend(["-a", "0", str(hash_file)])

        cmd.extend(self._cfg.extra_args)
        return cmd

    async def _read_potfile(self, potfile: Path) -> tuple[str, ...]:
        if not potfile.exists():  # noqa: ASYNC240
            return ()
        cracked: list[str] = []
        for line in potfile.read_text(errors="replace").splitlines():  # noqa: ASYNC240
            line = line.strip()
            if ":" in line:
                _, _, plaintext = line.rpartition(":")
                if plaintext:
                    cracked.append(plaintext)
        return tuple(cracked)

    def _error_result(
        self,
        job_id: str,
        mode: int,
        hash_file: str,
        potfile: str,
        started_at: str,
        t0: float,
        msg: str,
        tail: str,
    ) -> HashcatJobResult:
        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0
        return HashcatJobResult(
            job_id=job_id,
            mode=mode,
            hash_file=hash_file,
            cracked_credentials=(),
            potfile_path=potfile,
            return_code=-1,
            stdout_tail=tail,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=False,
            error_message=msg,
        )
