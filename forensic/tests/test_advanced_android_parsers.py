"""Tests for advanced Android system and messaging parsers matching Oxygen Forensics."""

import sqlite3
from pathlib import Path

from forensix_forensic.android_artifacts import (
    AndroidBluetoothDevicesParser,
    AndroidCellTowerParser,
    AndroidWifiProfilesParser,
    DiscordMessageParser,
    WeChatMessageParser,
    android_parser_registry,
)
from forensix_forensic.evidence_io import ParserContext, SafeSQLiteReader


def _context(locator: str) -> ParserContext:
    return ParserContext(
        case_id="case-100",
        evidence_source_id="src-100",
        working_copy_id="copy-100",
        source_sha256="0" * 64,
        source_label=locator,
        input_locator=locator,
        input_sha256="1" * 64,
    )


def test_wifi_profiles_parser(tmp_path: Path) -> None:
    db_path = tmp_path / "wifi.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE wifi_profiles (
            _id INTEGER PRIMARY KEY,
            ssid TEXT,
            bssid TEXT,
            psk TEXT,
            key_mgmt TEXT,
            latitude REAL,
            longitude REAL,
            last_connected INTEGER
        )
        """
    )
    conn.execute(
        """
        INSERT INTO wifi_profiles VALUES
        (1, 'SafeHouse_5G', '00:11:22:33:44:55', 'SecretPassword123', 'WPA2-PSK',
         37.7749, -122.4194, 1700000000000)
        """
    )
    conn.commit()
    conn.close()

    parser = AndroidWifiProfilesParser()
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _context("wifi.db"))

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.category == "location"
    assert art.subtype == "wifi_profile"
    assert "SafeHouse_5G" in art.title
    assert "00:11:22:33:44:55" in art.summary
    assert art.metadata["latitude"] == 37.7749


def test_bluetooth_devices_parser(tmp_path: Path) -> None:
    db_path = tmp_path / "bluetooth.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE bluetooth_devices (
            _id INTEGER PRIMARY KEY,
            name TEXT,
            address TEXT,
            device_class TEXT,
            last_connected INTEGER
        )
        """
    )
    conn.execute(
        """
        INSERT INTO bluetooth_devices VALUES
        (1, 'Suspect Smartwatch', 'AA:BB:CC:DD:EE:FF', 'Wearable', 1700000000000)
        """
    )
    conn.commit()
    conn.close()

    parser = AndroidBluetoothDevicesParser()
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _context("bluetooth.db"))

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.category == "system"
    assert art.subtype == "bluetooth_device"
    assert "Suspect Smartwatch" in art.title
    assert "AA:BB:CC:DD:EE:FF" in art.summary


def test_cell_tower_parser(tmp_path: Path) -> None:
    db_path = tmp_path / "telephony.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE cell_towers (
            _id INTEGER PRIMARY KEY,
            cid INTEGER,
            lac INTEGER,
            mcc INTEGER,
            mnc INTEGER,
            network_type TEXT,
            signal_strength INTEGER,
            latitude REAL,
            longitude REAL,
            timestamp INTEGER
        )
        """
    )
    conn.execute(
        """
        INSERT INTO cell_towers VALUES
        (1, 49201, 1042, 310, 410, 'LTE', -75, 40.7128, -74.0060, 1700000000000)
        """
    )
    conn.commit()
    conn.close()

    parser = AndroidCellTowerParser()
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _context("telephony.db"))

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.category == "location"
    assert art.subtype == "cell_tower_observation"
    assert "CID 49201" in art.title
    assert "MCC 310" in art.summary


def test_discord_message_parser(tmp_path: Path) -> None:
    db_path = tmp_path / "discord.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE discord_messages (
            _id INTEGER PRIMARY KEY,
            content TEXT,
            author_name TEXT,
            author_id TEXT,
            channel_name TEXT,
            channel_id TEXT,
            timestamp_ms INTEGER
        )
        """
    )
    conn.execute(
        """
        INSERT INTO discord_messages VALUES
        (1, 'Target package delivered to checkpoint B', 'OperativeX', '998877',
         'operations', '12345', 1700000000000)
        """
    )
    conn.commit()
    conn.close()

    parser = DiscordMessageParser()
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _context("discord.db"))

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.category == "communication"
    assert art.subtype == "discord_message"
    assert "OperativeX" in art.title
    assert "operations" in art.title
    assert "Target package delivered" in art.summary


def test_wechat_message_parser(tmp_path: Path) -> None:
    db_path = tmp_path / "wechat.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE wechat_message (
            msgId INTEGER PRIMARY KEY,
            talker TEXT,
            content TEXT,
            isSend INTEGER,
            createTime INTEGER
        )
        """
    )
    conn.execute(
        """
        INSERT INTO wechat_message VALUES
        (1001, 'contact_alpha_88', 'Wire transfer confirmed', 1, 1700000000000)
        """
    )
    conn.commit()
    conn.close()

    parser = WeChatMessageParser()
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _context("wechat.db"))

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.category == "communication"
    assert art.subtype == "wechat_message"
    assert "outgoing" in art.title
    assert "contact_alpha_88" in art.title
    assert "Wire transfer confirmed" in art.summary


def test_registry_contains_all_new_parsers() -> None:
    reg = android_parser_registry()
    ids = {m.parser_id for m in reg.metadata()}
    assert "android.wifi.profiles" in ids
    assert "android.bluetooth.devices" in ids
    assert "android.telephony.cell_towers" in ids
    assert "android.discord.messages" in ids
    assert "android.wechat.messages" in ids
