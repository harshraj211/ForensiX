from hashlib import sha256
from pathlib import Path

import pytest

from forensix_forensic.android_artifacts import (
    AndroidBluetoothConfigParser,
    AndroidDocumentParserError,
    AndroidWifiConfigParser,
    android_document_parser_registry,
)
from forensix_forensic.evidence_io import ParserContext


def _context(locator: str) -> ParserContext:
    return ParserContext(
        case_id="case",
        evidence_source_id="source",
        working_copy_id="copy",
        source_sha256="0" * 64,
        source_label=locator,
        input_locator=locator,
        input_sha256="1" * 64,
    )


def test_wifi_config_parses_network_without_exposing_credential(tmp_path: Path) -> None:
    path = tmp_path / "WifiConfigStore.xml"
    path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
        <WifiConfigStoreData><NetworkList><Network><WifiConfiguration>
          <string name="SSID">&quot;ForensiX Lab&quot;</string>
          <string name="ConfigKey">&quot;ForensiX Lab&quot;WPA_PSK</string>
          <string name="PreSharedKey">&quot;HighlySensitiveFixture&quot;</string>
        </WifiConfiguration></Network></NetworkList></WifiConfigStoreData>""",
        encoding="utf-8",
    )
    artifact = AndroidWifiConfigParser().parse(path, _context(path.name))[0]

    assert artifact.title == "Wi-Fi network: ForensiX Lab"
    assert artifact.metadata["credential_present"] is True
    assert artifact.metadata["credential_sha256"] == sha256(b'"HighlySensitiveFixture"').hexdigest()
    assert "HighlySensitiveFixture" not in str(artifact.metadata)
    assert "HighlySensitiveFixture" not in artifact.summary


def test_wifi_xml_rejects_entity_declarations(tmp_path: Path) -> None:
    path = tmp_path / "WifiConfigStore.xml"
    path.write_text(
        '<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><x>&secret;</x>',
        encoding="utf-8",
    )
    with pytest.raises(AndroidDocumentParserError, match="prohibited"):
        AndroidWifiConfigParser().parse(path, _context(path.name))


def test_bluetooth_config_hashes_link_key_and_registry_is_path_gated(tmp_path: Path) -> None:
    path = tmp_path / "bt_config.conf"
    path.write_text(
        """[Info]
FileSource = ForensiX fixture

[AA:BB:CC:DD:EE:FF]
Name = Known Headset
DevClass = 2360324
DevType = 1
Timestamp = 1704067200
LinkKey = 00112233445566778899AABBCCDDEEFF
""",
        encoding="utf-8",
    )
    artifact = AndroidBluetoothConfigParser().parse(path, _context(path.name))[0]
    registry = android_document_parser_registry()

    assert artifact.title == "Bluetooth device: Known Headset"
    assert artifact.event_time is not None and artifact.event_time.year == 2024
    assert artifact.metadata["link_key_present"] is True
    assert "00112233445566778899AABBCCDDEEFF" not in str(artifact.metadata)
    assert [
        item.metadata.parser_id
        for item in registry.compatible("data/misc/bluedroid/bt_config.conf")
    ] == ["android.bluetooth.config"]
    assert registry.compatible("unrelated.conf") == ()
