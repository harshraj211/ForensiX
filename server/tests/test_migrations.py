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
    inventory_item_columns = {
        column["name"] for column in inspect(engine).get_columns("acquisition_inventory_items")
    }
    evidence_source_columns = {
        column["name"] for column in inspect(engine).get_columns("evidence_sources")
    }

    assert {
        "alembic_version",
        "acquired_evidence_files",
        "acquisition_partials",
        "artifacts",
        "artifact_search",
        "source_artifact_search",
        "artifact_previews",
        "artifact_tags",
        "analyst_notes",
        "bookmarks",
        "tags",
        "timeline_events",
        "acquisition_inventories",
        "acquisition_inventory_items",
        "acquisition_plans",
        "auth_events",
        "auth_sessions",
        "audit_logs",
        "case_events",
        "case_device_assessments",
        "case_device_detections",
        "case_devices",
        "case_members",
        "cases",
        "custody_events",
        "custody_checkpoints",
        "custody_checkpoint_anchors",
        "custody_checkpoint_signatures",
        "device_capability_runs",
        "device_detection_runs",
        "evidence_verifications",
        "evidence_sources",
        "evidence_source_chunks",
        "evidence_source_verifications",
        "evidence_source_inspections",
        "evidence_recovery_assessments",
        "evidence_recovery_carving_runs",
        "evidence_external_recovery_runs",
        "evidence_parser_runs",
        "evidence_source_artifacts",
        "evidence_tool_outputs",
        "evidence_working_copies",
        "jobs",
        "job_events",
        "key_evidence",
        "media_analyses",
        "roles",
        "reports",
        "report_outputs",
        "report_review_events",
        "screen_recording_sessions",
        "system_events",
        "user_roles",
        "users",
    } <= tables
    assert {
        "size_bytes",
        "modified_time_raw",
        "modified_at",
        "timestamp_source",
        "timestamp_confidence",
    } <= inventory_item_columns
    assert {"chunks_storage_key", "chunks_sha256"} <= evidence_source_columns

    engine.dispose()
    command.downgrade(config, "base")
    downgraded_engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    downgraded_tables = set(inspect(downgraded_engine).get_table_names())

    assert "device_detection_runs" not in downgraded_tables
    assert "acquisition_plans" not in downgraded_tables
    assert "acquisition_inventories" not in downgraded_tables
    assert "acquisition_inventory_items" not in downgraded_tables
    assert "acquired_evidence_files" not in downgraded_tables
    assert "acquisition_partials" not in downgraded_tables
    assert "artifacts" not in downgraded_tables
    assert "artifact_search" not in downgraded_tables
    assert "source_artifact_search" not in downgraded_tables
    assert "artifact_previews" not in downgraded_tables
    assert "artifact_tags" not in downgraded_tables
    assert "analyst_notes" not in downgraded_tables
    assert "bookmarks" not in downgraded_tables
    assert "tags" not in downgraded_tables
    assert "timeline_events" not in downgraded_tables
    assert "evidence_verifications" not in downgraded_tables
    assert "evidence_sources" not in downgraded_tables
    assert "evidence_source_chunks" not in downgraded_tables
    assert "evidence_source_verifications" not in downgraded_tables
    assert "evidence_source_inspections" not in downgraded_tables
    assert "evidence_recovery_assessments" not in downgraded_tables
    assert "evidence_recovery_carving_runs" not in downgraded_tables
    assert "evidence_external_recovery_runs" not in downgraded_tables
    assert "evidence_parser_runs" not in downgraded_tables
    assert "evidence_source_artifacts" not in downgraded_tables
    assert "evidence_tool_outputs" not in downgraded_tables
    assert "evidence_working_copies" not in downgraded_tables
    assert "device_capability_runs" not in downgraded_tables
    assert "jobs" not in downgraded_tables
    assert "job_events" not in downgraded_tables
    assert "key_evidence" not in downgraded_tables
    assert "media_analyses" not in downgraded_tables
    assert "users" not in downgraded_tables
    assert "roles" not in downgraded_tables
    assert "user_roles" not in downgraded_tables
    assert "auth_sessions" not in downgraded_tables
    assert "auth_events" not in downgraded_tables
    assert "audit_logs" not in downgraded_tables
    assert "cases" not in downgraded_tables
    assert "custody_events" not in downgraded_tables
    assert "custody_checkpoints" not in downgraded_tables
    assert "custody_checkpoint_anchors" not in downgraded_tables
    assert "custody_checkpoint_signatures" not in downgraded_tables
    assert "case_members" not in downgraded_tables
    assert "case_events" not in downgraded_tables
    assert "case_device_assessments" not in downgraded_tables
    assert "case_device_detections" not in downgraded_tables
    assert "case_devices" not in downgraded_tables
    assert "system_events" not in downgraded_tables
    assert "reports" not in downgraded_tables
    assert "report_outputs" not in downgraded_tables
    assert "report_review_events" not in downgraded_tables
    assert "screen_recording_sessions" not in downgraded_tables
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
    assert "acquisition_inventories" in inspector.get_table_names()
    assert "acquisition_inventory_items" in inspector.get_table_names()
    assert "acquired_evidence_files" in inspector.get_table_names()
    assert "acquisition_partials" in inspector.get_table_names()
    assert "artifacts" in inspector.get_table_names()
    assert "artifact_search" in inspector.get_table_names()
    assert "source_artifact_search" in inspector.get_table_names()
    assert "artifact_previews" in inspector.get_table_names()
    assert "artifact_tags" in inspector.get_table_names()
    assert "analyst_notes" in inspector.get_table_names()
    assert "bookmarks" in inspector.get_table_names()
    assert "tags" in inspector.get_table_names()
    assert "timeline_events" in inspector.get_table_names()
    assert "evidence_source_timeline_events" in inspector.get_table_names()
    assert "root_access_probes" in inspector.get_table_names()
    assert "physical_block_probes" in inspector.get_table_names()
    parser_columns = {column["name"] for column in inspector.get_columns("evidence_parser_runs")}
    assert {"input_locator", "input_sha256"} <= parser_columns
    assert "evidence_verifications" in inspector.get_table_names()
    assert "custody_events" in inspector.get_table_names()
    assert "custody_checkpoints" in inspector.get_table_names()
    assert "custody_checkpoint_anchors" in inspector.get_table_names()
    assert "custody_checkpoint_signatures" in inspector.get_table_names()
    assert "audit_logs" in inspector.get_table_names()
    assert "key_evidence" in inspector.get_table_names()
    assert "media_analyses" in inspector.get_table_names()
    assert {"case_id", "plan_id", "checkpoint_json", "last_event_sequence"} <= job_columns
    preview_columns = {column["name"] for column in inspector.get_columns("artifact_previews")}
    media_columns = {column["name"] for column in inspector.get_columns("media_analyses")}
    assert {"source_width", "source_height", "media_metadata_json"} <= preview_columns
    assert {"analysis_hash", "gps_present", "perceptual_hash"} <= media_columns
    assert "report_review_events" in inspector.get_table_names()
    assert "evidence_recovery_assessments" in inspector.get_table_names()
    assert "evidence_recovery_carving_runs" in inspector.get_table_names()
    assert "evidence_external_recovery_runs" in inspector.get_table_names()
    assert "screen_recording_sessions" in inspector.get_table_names()
    report_columns = {column["name"] for column in inspector.get_columns("reports")}
    assert "redaction_profile" in report_columns
    recording_columns = {
        column["name"] for column in inspector.get_columns("screen_recording_sessions")
    }
    assert "mp4_storage_key" in recording_columns
    assert revision == "0042_source_artifact_search"
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
