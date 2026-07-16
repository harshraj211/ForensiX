from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from forensix_server.db import Database


def test_phase0_migration_upgrades_and_downgrades(tmp_path: Path) -> None:
    server_dir = Path(__file__).parents[1]
    database_path = tmp_path / "migration.db"
    config = Config(str(server_dir / "alembic.ini"))
    config.set_main_option("script_location", str(server_dir / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")

    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    tables = set(inspect(engine).get_table_names())

    assert {
        "alembic_version",
        "acquisition_plans",
        "auth_events",
        "auth_sessions",
        "case_events",
        "case_device_assessments",
        "case_device_detections",
        "case_devices",
        "case_members",
        "cases",
        "device_capability_runs",
        "device_detection_runs",
        "jobs",
        "job_events",
        "roles",
        "system_events",
        "user_roles",
        "users",
    } <= tables

    engine.dispose()
    command.downgrade(config, "base")
    downgraded_engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    downgraded_tables = set(inspect(downgraded_engine).get_table_names())

    assert "device_detection_runs" not in downgraded_tables
    assert "acquisition_plans" not in downgraded_tables
    assert "device_capability_runs" not in downgraded_tables
    assert "jobs" not in downgraded_tables
    assert "job_events" not in downgraded_tables
    assert "users" not in downgraded_tables
    assert "roles" not in downgraded_tables
    assert "user_roles" not in downgraded_tables
    assert "auth_sessions" not in downgraded_tables
    assert "auth_events" not in downgraded_tables
    assert "cases" not in downgraded_tables
    assert "case_members" not in downgraded_tables
    assert "case_events" not in downgraded_tables
    assert "case_device_assessments" not in downgraded_tables
    assert "case_device_detections" not in downgraded_tables
    assert "case_devices" not in downgraded_tables
    assert "system_events" not in downgraded_tables
    downgraded_engine.dispose()


def test_database_adopts_legacy_create_all_schema_before_upgrade(tmp_path: Path) -> None:
    server_dir = Path(__file__).parents[1]
    database_path = tmp_path / "legacy.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = Config(str(server_dir / "alembic.ini"))
    config.set_main_option("script_location", str(server_dir / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0007_acquisition_plans")

    legacy_engine = create_engine(database_url)
    with legacy_engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
    legacy_engine.dispose()

    database = Database(database_url, tmp_path)
    database.migrate()
    inspector = inspect(database.engine)
    job_columns = {column["name"] for column in inspector.get_columns("jobs")}
    with database.engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()

    assert "job_events" in inspector.get_table_names()
    assert {"case_id", "plan_id", "checkpoint_json", "last_event_sequence"} <= job_columns
    assert revision == "0008_job_events"
    database.dispose()


def test_database_refuses_to_stamp_unrecognized_legacy_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "unknown.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE unknown_product_data (id INTEGER PRIMARY KEY)"))
    engine.dispose()

    database = Database(database_url, tmp_path)
    with pytest.raises(RuntimeError, match="unrecognized"):
        database.migrate()
    database.dispose()
