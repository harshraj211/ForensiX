"""Closed known-answer fixture used only on controlled validation devices."""

import hashlib
from pathlib import Path

KNOWN_FILE_FIXTURE_ID = "forensix_shared_storage_v1"
KNOWN_FILE_RELATIVE_PATH = "Download/ForensiX-validation-v1.bin"
KNOWN_FILE_SIZE_BYTES = 65_595
KNOWN_FILE_SHA256 = "509fd710e724d86c67bf138c82655cfbd6b6da493b29132d3faa5149eeec2c73"


def known_file_payload() -> bytes:
    """Return the versioned deterministic fixture bytes."""
    payload = (
        b"ForensiX controlled physical-device validation fixture v1\r\n" + bytes(range(256)) * 256
    )
    if len(payload) != KNOWN_FILE_SIZE_BYTES:
        raise RuntimeError("Known-file fixture size invariant failed.")
    if hashlib.sha256(payload).hexdigest() != KNOWN_FILE_SHA256:
        raise RuntimeError("Known-file fixture hash invariant failed.")
    return payload


def write_known_file_fixture(destination: Path) -> None:
    """Create the fixture without overwriting an existing examiner file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(known_file_payload())
