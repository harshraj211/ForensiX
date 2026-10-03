"""User-exported collection bundles are verified before import."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

import pytest

from forensix_forensic.extractors.agent_apk import InvalidAgentBundle, import_agent_bundle
from forensix_forensic.extractors.agent_apk.bundle_import import _FILES


def _bundle(
    path: Path, *, tamper: bool = False, extra: bool = False, denied: bool = False,
    version: int = 1,
) -> str:
    collection_id = str(uuid4())
    files = {
        "contacts.json": b'[{"name":"Alice","phone_numbers":["123"],"emails":[],"account_type":"phone"}]',
        "sms.json": b"[]",
        "call_logs.json": b"[]",
        "installed_apps.json": b"[]",
        "device_metadata.json": b'{"source":"android_agent","category":"device_metadata","data":{},"availability_map":{}}',
        "app_artifacts.json": b"[]",
    }
    if version == 2:
        files.update(
            {
                "wifi_state.json": b'[{"wifi_enabled":true,"ssid":"LabNet","bssid":"00:11:22:33:44:55","rssi_dbm":-48,"link_speed_mbps":300,"frequency_mhz":5180,"network_id":7,"connected":true}]',
                "bluetooth_devices.json": b'[{"name":"Keyboard","address":"AA:BB:CC:DD:EE:FF","bond_state":12,"device_type":1,"bluetooth_class":1344}]',
                "sim_metadata.json": b'[{"subscription_id":1,"slot_index":0,"carrier_name":"Carrier","display_name":"SIM 1","mcc":"310","mnc":"260","country_iso":"us","iccid":"8901","carrier_id":123}]',
            }
        )
    manifest = {
        "format": f"forensix-agent-v{version}",
        "collection_id": collection_id,
        "created_at_ms": 1,
        "mode": "user_export",
        "files": {
            name: {"sha256": sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in files.items()
        },
    }
    if denied:
        manifest["complete"] = False
        manifest["files"]["sms.json"]["status"] = "permission_denied"
    with ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in files.items():
            archive.writestr(name, data + b"tampered" if tamper and name == "sms.json" else data)
        if extra:
            archive.writestr("../unexpected.txt", "bad")
    return collection_id


def test_user_export_imports_without_adb(tmp_path: Path) -> None:
    path = tmp_path / "collection.fxz"
    collection_id = _bundle(path)
    result = import_agent_bundle(path, case_id="CASE-001", output_dir=tmp_path / "imported")
    assert result.success
    assert result.extraction_id == collection_id
    assert result.contacts[0].name == "Alice"
    assert (Path(result.output_dir) / "manifest.json").is_file()


def test_android_export_and_desktop_import_file_contract() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "agent_apk/forensix_agent/app/src/main/java/com/forensix/agent/AgentService.java"
    ).read_text(encoding="utf-8")
    block = source.split("static final String[] OUTPUT_FILES = {", 1)[1].split("};", 1)[0]
    android_files = set(re.findall(r'"([a-z_]+\.json)"', block))
    assert android_files == _FILES


def test_denied_source_is_not_reported_as_complete(tmp_path: Path) -> None:
    path = tmp_path / "collection.fxz"
    _bundle(path, denied=True)
    result = import_agent_bundle(path, case_id="CASE-001", output_dir=tmp_path / "imported")
    assert not result.success
    assert result.error_message == "Collection has denied or incomplete sources"


def test_v2_bundle_imports_network_bluetooth_and_sim_records(tmp_path: Path) -> None:
    path = tmp_path / "collection-v2.fxz"
    _bundle(path, version=2)
    result = import_agent_bundle(path, case_id="CASE-002", output_dir=tmp_path / "imported")
    assert result.wifi_states[0].ssid == "LabNet"
    assert result.bluetooth_devices[0].address == "AA:BB:CC:DD:EE:FF"
    assert result.sim_subscriptions[0].iccid == "8901"


@pytest.mark.parametrize("tamper,extra", [(True, False), (False, True)])
def test_rejects_corrupt_or_unexpected_files(tmp_path: Path, tamper: bool, extra: bool) -> None:
    path = tmp_path / "collection.fxz"
    _bundle(path, tamper=tamper, extra=extra)
    with pytest.raises(InvalidAgentBundle):
        import_agent_bundle(path, case_id="CASE-001", output_dir=tmp_path / "imported")
    assert not list((tmp_path / "imported").glob("*/manifest.json"))
