# ruff: noqa: S603, S607
"""Generic APK Downgrade Handler — 46-app manifest driven extraction."""

from __future__ import annotations

import io
import logging
import subprocess
import tarfile
import time
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from forensix_server.db.models import JobRecord
from forensix_server.jobs.domain import JobState
from forensix_server.jobs.service import JobService

from ._common import (
    AcquisitionError,
    _adb,
    resolve_vault,
    update_progress,
    verify_device_online,
    write_result,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 46-App APK downgrade manifest
# ---------------------------------------------------------------------------

APK_DOWNGRADE_MANIFEST: dict[str, str] = {
    "com.whatsapp": "whatsapp_legacy_2_22.apk",
    "org.telegram.messenger": "telegram_legacy_9_6.apk",
    "com.instagram.android": "instagram_legacy_275.apk",
    "com.snapchat.android": "snapchat_legacy_12_10.apk",
    "com.facebook.katana": "facebook_legacy_425.apk",
    "com.twitter.android": "twitter_legacy_9_80.apk",
    "com.discord": "discord_legacy_126.apk",
    "org.thoughtcrime.securesms": "signal_legacy_6_37.apk",
    "com.facebook.orca": "messenger_legacy_390.apk",
    "com.kakao.talk": "kakaotalk_legacy_9_4.apk",
    "com.viber.voip": "viber_legacy_17_5.apk",
    "com.tencent.mm": "wechat_legacy_8_0.apk",
    "jp.naver.line.android": "line_legacy_13_2.apk",
    "kik.android": "kik_legacy_15_40.apk",
    "com.imo.android.imoim": "imo_legacy_2022_8.apk",
    "com.skype.raider": "skype_legacy_8_90.apk",
    "com.loudtalks": "zello_legacy_4_91.apk",
    "com.opera.browser": "opera_legacy_75.apk",
    "com.zhiliaoapp.musically": "tiktok_legacy_27_2.apk",
    "com.google.android.gm": "gmail_legacy_2022_8.apk",
    "com.android.chrome": "chrome_legacy_105.apk",
    "org.mozilla.firefox": "firefox_legacy_104.apk",
    "com.brave.browser": "brave_legacy_1_43.apk",
    "com.duckduckgo.mobile.android": "duckduckgo_legacy_5_122.apk",
    "network.loki.messenger": "session_legacy_1_14.apk",
    "im.vector.app": "element_legacy_1_5.apk",
    "ch.threema.app": "threema_legacy_4_72.apk",
    "com.vkontakte.android": "vk_legacy_7_34.apk",
    "chat.tamtam": "tamtam_legacy_3_37.apk",
    "com.sec.android.app.sbrowser": "samsung_browser_legacy_18.apk",
    "com.microsoft.emmx": "edge_legacy_105.apk",
    "com.reddit.frontpage": "reddit_legacy_2022_34.apk",
    "com.linkedin.android": "linkedin_legacy_4_1_627.apk",
    "com.pinterest": "pinterest_legacy_10_14.apk",
    "com.google.android.youtube": "youtube_legacy_17_36.apk",
    "com.spotify.music": "spotify_legacy_8_7.apk",
    "com.google.android.apps.docs": "google_drive_legacy_2_22.apk",
    "com.google.android.apps.photos": "google_photos_legacy_5_79.apk",
    "com.microsoft.office.outlook": "outlook_legacy_4_2214.apk",
    "com.microsoft.teams": "teams_legacy_1416.apk",
    "com.google.android.apps.maps": "google_maps_legacy_11_24.apk",
    "com.dropbox.android": "dropbox_legacy_299.apk",
    "com.microsoft.skydrive": "onedrive_legacy_6_48.apk",
    "nz.mega.android": "mega_legacy_10_0.apk",
    "com.box.android": "box_legacy_5_18.apk",
    "com.google.android.keep": "google_keep_legacy_5_22.apk",
}

# Decoder routing
_DECODER_MAP: dict[str, str] = {
    "com.whatsapp": "whatsapp",
    "org.telegram.messenger": "telegram",
    "com.instagram.android": "instagram",
    "com.snapchat.android": "snapchat",
}

_MIN_BACKUP_BYTES = 100 * 1024
_MIN_ORIGINAL_BYTES = 2 * 1024 * 1024


def get_apk_manifest_info(serial: str) -> list[dict[str, Any]]:
    """Return list of {package, legacy_apk, installed} for the 46-app manifest."""
    installed: set[str] = set()
    try:
        out = subprocess.run(
            ["adb", "-s", serial, "shell", "pm list packages"],
            capture_output=True,
            timeout=30,
            text=True,
            encoding="utf-8",
        ).stdout
        for line in out.splitlines():
            if line.startswith("package:"):
                installed.add(line.replace("package:", "").strip())
    except Exception as error:  # noqa: BLE001
        logger.warning("Package inventory failed: %s", error)

    return [
        {
            "package": pkg,
            "legacy_apk": apk_file,
            "installed": pkg in installed,
        }
        for pkg, apk_file in APK_DOWNGRADE_MANIFEST.items()
    ]


def handle_generic_downgrade(session: Session, job: JobRecord, params: dict[str, Any]) -> None:
    """Execute APK downgrade extraction for a single package from the 46-app manifest.

    Required params:
      serial         — ADB device serial
      package_name   — one of the keys in APK_DOWNGRADE_MANIFEST
    """
    serial: str = params.get("serial", "emulator-5554")
    package_name: str = params.get("package_name", "")
    case_id: str = job.case_id or params.get("case_id", "unknown")
    vault = resolve_vault(params, case_id)

    project_root = Path(__file__).resolve().parents[6]
    legacy_apk_dir = project_root / "assets" / "legacy_apks"

    result: dict[str, Any] = {
        "serial": serial,
        "case_id": case_id,
        "package": package_name,
        "steps": {},
        "started_at": datetime.now(UTC).isoformat(),
    }

    svc = JobService()
    svc.transition(session, job.id, JobState.RUNNING)
    session.commit()

    try:
        # Validate package
        update_progress(session, job, 5, step="[1/6] Validating package manifest")
        if package_name not in APK_DOWNGRADE_MANIFEST:
            raise AcquisitionError(f"Package {package_name!r} not in the 46-app downgrade manifest")
        legacy_filename = APK_DOWNGRADE_MANIFEST[package_name]
        legacy_apk = legacy_apk_dir / legacy_filename

        verify_device_online(serial)

        # Check installed
        pm_check = _adb(serial, "shell", f"pm list packages {package_name}", timeout=20)
        if package_name not in pm_check:
            raise AcquisitionError(f"{package_name} is not installed on device {serial}")

        # Step 1: Save original APK
        update_progress(session, job, 15, step="[2/6] Saving original APK")
        pm_out = _adb(serial, "shell", f"pm path {package_name}", timeout=20)
        if "package:" not in pm_out:
            raise AcquisitionError(f"Cannot resolve APK path for {package_name}")
        original_apk_path = pm_out.split("package:")[1].strip()
        original_local = vault / f"{package_name.replace('.', '_')}_original.apk"
        _adb(serial, "pull", original_apk_path, str(original_local), timeout=120)

        if not original_local.exists() or original_local.stat().st_size < _MIN_ORIGINAL_BYTES:
            raise AcquisitionError(
                "Original APK too small or missing. Aborting before device mutation."
            )
        result["steps"]["save_original"] = {
            "status": "completed",
            "size_bytes": original_local.stat().st_size,
        }

        ab_path = vault / f"{package_name.replace('.', '_')}_backup.ab"
        db_path = vault / f"{package_name.replace('.', '_')}_extracted.db"

        try:
            # Step 2: Install legacy APK
            update_progress(session, job, 30, step="[3/6] Installing legacy APK")
            if not legacy_apk.exists():
                raise AcquisitionError(
                    f"Legacy APK not found: {legacy_apk}. "
                    f"Place {legacy_filename} in assets/legacy_apks/"
                )
            _adb(serial, "install", "-r", "-d", str(legacy_apk), timeout=60)
            result["steps"]["install_legacy"] = {"status": "completed"}

            # Step 3: ADB backup
            update_progress(session, job, 50, step="[4/6] Running adb backup")
            time.sleep(3)  # give app time to settle after install
            subprocess.run(
                ["adb", "-s", serial, "backup", "-f", str(ab_path), package_name],
                capture_output=True,
                timeout=90,
            )
            if not ab_path.exists() or ab_path.stat().st_size < _MIN_BACKUP_BYTES:
                raise AcquisitionError(
                    f"Backup too small ({ab_path.stat().st_size if ab_path.exists() else 0} bytes)"
                )
            result["steps"]["adb_backup"] = {
                "status": "completed",
                "bytes": ab_path.stat().st_size,
            }

            # Step 4: Extract primary DB
            update_progress(session, job, 70, step="[5/6] Extracting database from backup")
            result["steps"]["extract_db"] = _extract_db_from_ab(ab_path, db_path, package_name)

        finally:
            # Always restore
            update_progress(session, job, 85, step="[6/6] Restoring original APK")
            restore_res = _restore_apk(serial, original_local)
            result["steps"]["restore_original"] = restore_res

        # Route to decoder
        if db_path.exists() and db_path.stat().st_size > 0:
            result["steps"]["decode"] = _route_decoder(db_path, package_name, vault)

        result["completed_at"] = datetime.now(UTC).isoformat()
        write_result(session, job, result)
        svc.update_progress(session, job.id, 100, current_step="Generic Downgrade completed")
        svc.transition(session, job.id, JobState.COMPLETED)
        session.commit()

    except AcquisitionError as exc:
        logger.error("GenericDowngrade AcquisitionError: %s", exc)
        result["error"] = str(exc)
        write_result(session, job, result)
        svc.transition(
            session,
            job.id,
            JobState.FAILED,
            error_code="ACQUISITION_ERROR",
            error_message=str(exc),
        )
        session.commit()
        raise

    except subprocess.TimeoutExpired as exc:
        msg = f"ADB timeout: {exc}"
        result["error"] = msg
        write_result(session, job, result)
        svc.transition(
            session,
            job.id,
            JobState.FAILED,
            error_code="ADB_TIMEOUT",
            error_message=msg,
        )
        session.commit()
        raise AcquisitionError(msg) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_db_from_ab(ab_path: Path, out_path: Path, package_name: str) -> dict[str, Any]:
    """Decompress .ab and extract the first .db from the app's data directory."""
    try:
        raw = ab_path.read_bytes()
        header_end = 24
        nl_count = 0
        for i, b in enumerate(raw[:300]):
            if b == ord("\n"):
                nl_count += 1
                if nl_count == 4:
                    header_end = i + 1
                    break

        compressed = raw[header_end:]
        try:
            decompressed = zlib.decompress(compressed, -15)
        except zlib.error:
            decompressed = zlib.decompress(compressed)

        # Extract first .db that isn't a WAL or SHM
        found = False
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as tf:
            for member in tf.getmembers():
                name = member.name.lower()
                if name.endswith(".db") and not name.endswith(
                    ("-wal", "-shm", ".db-wal", ".db-shm")
                ):
                    f = tf.extractfile(member)
                    if f:
                        out_path.write_bytes(f.read())
                        found = True
                        break

        if found:
            return {"status": "completed", "file": out_path.name, "bytes": out_path.stat().st_size}
        return {"status": "failed", "error": "no .db file found in backup"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _restore_apk(serial: str, local_apk: Path) -> dict[str, Any]:
    if not local_apk.exists():
        return {"status": "failed", "error": "original APK not found locally"}
    try:
        res = subprocess.run(
            ["adb", "-s", serial, "install", "-r", str(local_apk)],
            capture_output=True,
            timeout=90,
            text=True,
            encoding="utf-8",
        )
        if res.returncode != 0:
            return {"status": "failed", "error": res.stderr.strip()}
        return {"status": "completed"}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "restore timeout (90s)"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def _route_decoder(db_path: Path, package_name: str, vault: Path) -> dict[str, Any]:
    """Route extracted .db to the appropriate decoder or generic SQLite carver."""
    import sqlite3

    decoder_type = _DECODER_MAP.get(package_name, "sqlite_generic")

    try:
        con = sqlite3.connect(str(db_path))
        tables = [
            r[0]
            for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]
        row_count = 0
        for tbl in tables[:5]:
            try:
                cnt = con.execute(f'SELECT COUNT(*) FROM "{tbl}"').fetchone()  # noqa: S608
                row_count += cnt[0] if cnt else 0
            except sqlite3.OperationalError:
                continue
        con.close()
        return {
            "status": "completed",
            "decoder": decoder_type,
            "tables": tables,
            "approx_row_count": row_count,
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "decoder": decoder_type, "error": str(exc)}
