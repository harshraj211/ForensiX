"""SQLite engine lifecycle with forensic-safe durability defaults."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .base import Base


class Database:
    def __init__(self, database_url: str, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self._data_dir = data_dir.resolve()
        self.engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False, "timeout": 5.0},
            pool_pre_ping=True,
        )
        event.listen(self.engine, "connect", _configure_sqlite_connection)
        self._session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
        )

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

    def migrate(self) -> None:
        """Upgrade a workstation database, safely adopting legacy create-all schemas."""
        server_dir = Path(__file__).resolve().parents[3]
        config = Config(str(server_dir / "alembic.ini"))
        config.set_main_option("script_location", str(server_dir / "alembic"))
        config.set_main_option(
            "sqlalchemy.url",
            self.engine.url.render_as_string(hide_password=False).replace("%", "%%"),
        )
        inspector = inspect(self.engine)
        tables = set(inspector.get_table_names())
        if tables and "alembic_version" not in tables:
            inventory_columns = (
                {column["name"] for column in inspector.get_columns("acquisition_inventory_items")}
                if "acquisition_inventory_items" in tables
                else set()
            )
            evidence_source_columns = (
                {column["name"] for column in inspector.get_columns("evidence_sources")}
                if "evidence_sources" in tables
                else set()
            )
            parser_run_columns = (
                {column["name"] for column in inspector.get_columns("evidence_parser_runs")}
                if "evidence_parser_runs" in tables
                else set()
            )
            legacy_revision = _legacy_revision(
                tables, inventory_columns, evidence_source_columns, parser_run_columns
            )
            command.stamp(config, legacy_revision)
        command.upgrade(config, "head")

    def ready(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:  # readiness boundary intentionally converts driver failures
            return False
        return True

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()


def _configure_sqlite_connection(dbapi_connection: object, _: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


def sqlite_pragmas(engine: Engine) -> dict[str, int | str]:
    with engine.connect() as connection:
        return {
            "foreign_keys": connection.execute(text("PRAGMA foreign_keys")).scalar_one(),
            "journal_mode": connection.execute(text("PRAGMA journal_mode")).scalar_one(),
            "synchronous": connection.execute(text("PRAGMA synchronous")).scalar_one(),
            "busy_timeout": connection.execute(text("PRAGMA busy_timeout")).scalar_one(),
        }


def _legacy_revision(
    tables: set[str],
    inventory_columns: set[str],
    evidence_source_columns: set[str],
    parser_run_columns: set[str],
) -> str:
    """Identify the newest schema marker created before migration tracking was enabled."""
    if "evidence_sources" in tables:
        if "physical_block_probes" in tables:
            return "0028_physical_block_probes"
        if "input_locator" in parser_run_columns:
            return "0027_parser_input_provenance"
        if "root_access_probes" in tables:
            return "0026_root_access_probes"
        if "evidence_source_timeline_events" in tables:
            return "0025_evidence_twin_provenance"
        if "evidence_tool_outputs" in tables:
            return "0024_aleapp_outputs"
        if "evidence_parser_runs" in tables:
            return "0023_evidence_parser_results"
        if "evidence_source_inspections" in tables:
            return "0022_evidence_twin_inspection"
        if "chunks_storage_key" in evidence_source_columns:
            return "0021_evidence_twin_chunk_manifest"
        return "0020_evidence_twin_foundation"
    if "report_outputs" in tables and "modified_at" in inventory_columns:
        return "0018_source_timestamps"
    markers = (
        ("report_outputs", "0017_reports_exports"),
        ("artifact_previews", "0016_safe_previews"),
        ("timeline_events", "0015_timeline_analysis"),
        ("artifacts", "0014_artifacts_search"),
        ("acquisition_partials", "0013_partial_recovery"),
        ("custody_events", "0012_custody_audit"),
        ("evidence_verifications", "0011_verifications"),
        ("acquired_evidence_files", "0010_evidence_files"),
        ("acquisition_inventories", "0009_inventory"),
        ("job_events", "0008_job_events"),
        ("acquisition_plans", "0007_acquisition_plans"),
        ("case_devices", "0006_case_devices"),
        ("cases", "0005_cases"),
        ("users", "0004_auth_rbac"),
        ("jobs", "0003_jobs"),
        ("device_capability_runs", "0002_capabilities"),
        ("device_detection_runs", "0001_phase0"),
    )
    for table, revision in markers:
        if table in tables:
            return revision
    raise RuntimeError(
        "The configured database has unrecognized tables and cannot be adopted automatically."
    )
