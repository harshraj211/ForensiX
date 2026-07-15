from pathlib import Path

from forensix_server.db import Database
from forensix_server.db.database import sqlite_pragmas


def test_sqlite_durability_pragmas(tmp_path: Path) -> None:
    database = Database(f"sqlite:///{(tmp_path / 'test.db').as_posix()}", tmp_path)
    database.initialize()

    pragmas = sqlite_pragmas(database.engine)

    assert pragmas["foreign_keys"] == 1
    assert str(pragmas["journal_mode"]).lower() == "wal"
    assert pragmas["synchronous"] == 2
    assert pragmas["busy_timeout"] == 5000
    assert database.ready()
    database.dispose()
