"""Tests for Android Cloud Tokens and Multi-User Parsers."""

import sqlite3
from pathlib import Path

from forensix_forensic.android_artifacts.cloud_tokens import AndroidCloudTokensParser
from forensix_forensic.android_artifacts.system import AndroidUsersParser
from forensix_forensic.evidence_io import ParserContext, SafeSQLiteReader


def _context(locator: str = "test.db") -> ParserContext:
    return ParserContext(
        case_id="case_test",
        evidence_source_id="src_1",
        working_copy_id="copy_1",
        input_locator=locator,
        source_sha256="0" * 64,
        source_label="test",
    )


def test_android_cloud_tokens_parser(tmp_path: Path):
    db_path = tmp_path / "accounts_ce.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE accounts (
            _id INTEGER PRIMARY KEY,
            name TEXT,
            type TEXT,
            password TEXT,
            previous_name TEXT,
            last_password_entry_time_millis_epoch INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE authtokens (
            _id INTEGER PRIMARY KEY,
            accounts_id INTEGER,
            type TEXT,
            authtoken TEXT
        )
        """
    )
    conn.execute(
        """
        INSERT INTO accounts VALUES
        (1, 'suspect@gmail.com', 'com.google', NULL, NULL, 1700000000000)
        """
    )
    conn.execute(
        """
        INSERT INTO authtokens VALUES
        (1, 1, 'oauth2_master_token', 'ya29.a0AfH6SMD...')
        """
    )
    conn.commit()
    conn.close()

    parser = AndroidCloudTokensParser()
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _context("accounts_ce.db"))

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.category == "system"
    assert art.subtype == "cloud_account_token"
    assert "suspect@gmail.com" in art.title
    assert "Google Account / Drive" in art.title
    assert art.metadata["service_label"] == "Google Account / Drive"


def test_android_users_parser(tmp_path: Path):
    db_path = tmp_path / "users.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            flags INTEGER,
            serial_number INTEGER,
            user_type TEXT,
            profile_group_id INTEGER,
            restricted INTEGER,
            created_at INTEGER
        )
        """
    )
    conn.execute(
        """
        INSERT INTO users VALUES
        (0, 'Owner', 19, 0, 'android.os.usertype.full.SYSTEM', -10000, 0, 1690000000000),
        (10, 'Work Knox', 48, 10, 'android.os.usertype.profile.MANAGED', 0, 1, 1695000000000),
        (11, 'Dual Space Clone', 32, 11, 'android.os.usertype.profile.CLONE', 0, 0, 1698000000000)
        """
    )
    conn.commit()
    conn.close()

    parser = AndroidUsersParser()
    with SafeSQLiteReader(db_path) as reader:
        artifacts = parser.parse(reader, _context("users.db"))

    assert len(artifacts) == 3
    u0, u10, u11 = artifacts
    assert u0.title == "Android User 0: Owner"
    assert u0.metadata["sandbox_path"] == "/data/user/0/"
    assert u10.title == "Android User 10: Work Knox"
    assert u10.metadata["sandbox_path"] == "/data/user/10/"
    assert u11.title == "Android User 11: Dual Space Clone"
    assert u11.metadata["sandbox_path"] == "/data/user/11/"
