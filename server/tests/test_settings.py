from hashlib import sha256
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


def test_plain_http_transport_is_loopback_only() -> None:
    assert not Settings(environment="production").secure_cookies
    assert Settings(deployment_transport="https").secure_cookies

    with pytest.raises(ValidationError, match="restricted to a loopback host"):
        Settings(api_host=".".join(["0"] * 4))


def test_settings_require_complete_aleapp_pin(tmp_path: Path) -> None:
    program = tmp_path / "aleapp.py"
    program.write_text("print('fixture')", encoding="utf-8")

    with pytest.raises(ValidationError, match="configured together"):
        Settings(aleapp_program_path=program)

    settings = Settings(
        aleapp_program_path=program,
        aleapp_expected_sha256=sha256(program.read_bytes()).hexdigest(),
        aleapp_release_label="v2026.1.0-test",
    )

    runner = settings.aleapp_runner()
    assert runner is not None
    assert runner.diagnose().hash_verified


def test_settings_require_complete_photorec_pin(tmp_path: Path) -> None:
    executable = tmp_path / "photorec_win.exe"
    executable.write_bytes(b"photorec fixture")

    with pytest.raises(ValidationError, match="configured together"):
        Settings(photorec_path=executable)

    settings = Settings(
        photorec_path=executable,
        photorec_expected_sha256=sha256(executable.read_bytes()).hexdigest(),
    )

    assert settings.photorec_controller().diagnose().available
