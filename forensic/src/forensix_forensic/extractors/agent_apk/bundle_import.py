"""Import a user-exported Android agent bundle without ADB.

The SHA-256 entries detect accidental corruption or changes relative to the
bundle manifest. They do not authenticate the device or the agent; a signing
or enrollment protocol is required before accepting remote/unattended uploads.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import UUID
from zipfile import BadZipFile, ZipFile

from .agent_result import (
    AgentExtractionResult,
    app_artifacts_from_json,
    call_logs_from_json,
    contacts_from_json,
    device_metadata_from_json,
    installed_apps_from_json,
    bluetooth_devices_from_json,
    sim_subscriptions_from_json,
    sms_from_json,
    wifi_states_from_json,
)

_V1_FILES = frozenset(
    {
        "contacts.json",
        "sms.json",
        "call_logs.json",
        "installed_apps.json",
        "device_metadata.json",
        "app_artifacts.json",
    }
)
_V2_FILES = _V1_FILES | frozenset({"wifi_state.json", "bluetooth_devices.json", "sim_metadata.json"})
# Kept as the current desktop/Android export contract for callers and tests.
_FILES = _V2_FILES
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024


class InvalidAgentBundle(ValueError):
    """The exported bundle is malformed, incomplete, or hash-inconsistent."""


def import_agent_bundle(
    bundle_path: Path, *, case_id: str, output_dir: Path
) -> AgentExtractionResult:
    """Verify and import one locally selected `.fxz` file into a new directory."""
    if not case_id or len(case_id) > 128:
        raise ValueError("A case ID of 1–128 characters is required")
    output_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".agent-import-", dir=output_dir))
    try:
        with ZipFile(bundle_path) as archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            if any(item.is_dir() or item.file_size > _MAX_FILE_BYTES for item in members):
                raise InvalidAgentBundle("Bundle contains a directory or oversized file")
            if sum(item.file_size for item in members) > _MAX_TOTAL_BYTES:
                raise InvalidAgentBundle("Bundle exceeds the import size limit")
            if archive.getinfo("manifest.json").file_size > 1024 * 1024:
                raise InvalidAgentBundle("Manifest is too large")
            manifest_bytes = _bounded_read(archive, "manifest.json", 1024 * 1024)
            manifest = json.loads(manifest_bytes)
            if not isinstance(manifest, dict) or manifest.get("format") not in {"forensix-agent-v1", "forensix-agent-v2"}:
                raise InvalidAgentBundle("Unsupported agent bundle format")
            expected_files = _V2_FILES if manifest["format"] == "forensix-agent-v2" else _V1_FILES
            if len(names) != len(set(names)) or set(names) != expected_files | {"manifest.json"}:
                raise InvalidAgentBundle("Bundle has missing, duplicate, or unexpected files")
            try:
                collection_id = str(UUID(manifest["collection_id"]))
            except (KeyError, ValueError, TypeError) as exc:
                raise InvalidAgentBundle("Invalid collection ID") from exc
            declared = manifest.get("files")
            if not isinstance(declared, dict) or set(declared) != expected_files:
                raise InvalidAgentBundle("Manifest file list does not match bundle")
            if not isinstance(manifest.get("complete", True), bool):
                raise InvalidAgentBundle("Invalid completion state")
            complete = manifest.get("complete", True)
            parsed: dict[str, object] = {}
            total_read = len(manifest_bytes)
            for name in sorted(expected_files):
                metadata = declared[name]
                if not isinstance(metadata, dict):
                    raise InvalidAgentBundle(f"Missing metadata for {name}")
                status = metadata.get("status", "ok")
                if status not in {
                    "ok", "permission_denied", "provider_unavailable", "partial_error",
                    "visibility_limited", "storage_limited",
                }:
                    raise InvalidAgentBundle(f"Invalid status for {name}")
                if status != "ok":
                    complete = False
                data = _bounded_read(archive, name, _MAX_FILE_BYTES)
                total_read += len(data)
                if total_read > _MAX_TOTAL_BYTES:
                    raise InvalidAgentBundle("Bundle exceeds the import size limit")
                if metadata.get("bytes") != len(data) or metadata.get("sha256") != sha256(data).hexdigest():
                    raise InvalidAgentBundle(f"Hash or size mismatch for {name}")
                parsed[name] = json.loads(data)
                (staging / name).write_bytes(data)
            (staging / "manifest.json").write_bytes(manifest_bytes)
        if not all(isinstance(parsed[name], list) for name in expected_files - {"device_metadata.json"}):
            raise InvalidAgentBundle("Expected list data in collection files")
        if any(
            not isinstance(item, dict)
            for name in expected_files - {"device_metadata.json"}
            for item in parsed[name]
        ):
            raise InvalidAgentBundle("Expected object records in collection files")
        if not isinstance(parsed["device_metadata.json"], dict):
            raise InvalidAgentBundle("Expected device metadata object")
        try:
            contacts = contacts_from_json(parsed["contacts.json"])
            sms = sms_from_json(parsed["sms.json"])
            calls = call_logs_from_json(parsed["call_logs.json"])
            apps = installed_apps_from_json(parsed["installed_apps.json"])
            metadata = device_metadata_from_json(parsed["device_metadata.json"])
            artifacts = app_artifacts_from_json(parsed["app_artifacts.json"])
            wifi_states = wifi_states_from_json(parsed.get("wifi_state.json"))
            bluetooth_devices = bluetooth_devices_from_json(parsed.get("bluetooth_devices.json"))
            sim_subscriptions = sim_subscriptions_from_json(parsed.get("sim_metadata.json"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise InvalidAgentBundle("Collection records are malformed") from exc
        destination = output_dir / collection_id
        if destination.exists():
            raise InvalidAgentBundle("Collection ID has already been imported")
        os.replace(staging, destination)
        now = datetime.now(UTC).isoformat()
        return AgentExtractionResult(
            extraction_id=collection_id,
            device_serial=f"offline:{collection_id}",
            case_id=case_id,
            contacts=contacts,
            sms_messages=sms,
            call_logs=calls,
            installed_apps=apps,
            media_file_count=sum(1 for item in artifacts if item.artifact_category == "media"),
            output_dir=str(destination),
            timeline=[{"ts": now, "event": "user_export_bundle_imported", "complete": complete}],
            started_at=now,
            finished_at=now,
            duration_seconds=0.0,
            success=complete,
            error_message=None if complete else "Collection has denied or incomplete sources",
            device_metadata=metadata,
            app_artifacts=artifacts,
            wifi_states=wifi_states,
            bluetooth_devices=bluetooth_devices,
            sim_subscriptions=sim_subscriptions,
        )
    except (BadZipFile, KeyError, json.JSONDecodeError) as exc:
        raise InvalidAgentBundle("Bundle is corrupt or contains invalid JSON") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _bounded_read(archive: ZipFile, name: str, maximum: int) -> bytes:
    with archive.open(name) as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise InvalidAgentBundle(f"Oversized file: {name}")
    return data
