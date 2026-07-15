from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


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
        "auth_events",
        "auth_sessions",
        "device_capability_runs",
        "device_detection_runs",
        "jobs",
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
    assert "device_capability_runs" not in downgraded_tables
    assert "jobs" not in downgraded_tables
    assert "users" not in downgraded_tables
    assert "roles" not in downgraded_tables
    assert "user_roles" not in downgraded_tables
    assert "auth_sessions" not in downgraded_tables
    assert "auth_events" not in downgraded_tables
    assert "system_events" not in downgraded_tables
    downgraded_engine.dispose()
