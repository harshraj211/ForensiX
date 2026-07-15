from pathlib import Path

import pytest
from pydantic import ValidationError

from forensix_server.config import Settings


def test_settings_build_local_sqlite_url(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)

    assert settings.resolved_database_url.endswith("/forensix.db")


def test_settings_reject_wildcard_origin() -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_origins=("*",))
