import pytest

from forensix_forensic.adb import MAX_ROOTED_BUNDLE_BYTES
from forensix_server.evidence_twin.domain import MINIMUM_FREE_BYTES
from forensix_server.rooted.service import (
    RootedDeviceError,
    _require_userdata_snapshot_ready,
)


def test_userdata_snapshot_requires_confirmed_unlocked_credential_storage() -> None:
    with pytest.raises(RootedDeviceError, match="did not confirm"):
        _require_userdata_snapshot_ready(
            {"sys.user.0.ce_available": "false"},
            MAX_ROOTED_BUNDLE_BYTES * 3,
        )


def test_userdata_snapshot_requires_space_for_temporary_and_sealed_copies() -> None:
    with pytest.raises(RootedDeviceError, match="17 GiB"):
        _require_userdata_snapshot_ready(
            {"sys.user.0.ce_available": "true"},
            MAX_ROOTED_BUNDLE_BYTES,
        )


def test_userdata_snapshot_accepts_unlocked_device_with_required_space() -> None:
    _require_userdata_snapshot_ready(
        {"sys.user.0.ce_available": "1"},
        MAX_ROOTED_BUNDLE_BYTES * 2 + MINIMUM_FREE_BYTES,
    )
