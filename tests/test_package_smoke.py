from forensix_api import __version__ as api_version
from forensix_forensic import __version__ as forensic_version
from forensix_server import __version__ as server_version


def test_workspace_packages_are_importable() -> None:
    assert api_version == "1.0.0"
    assert forensic_version == "1.0.0"
    assert server_version == "1.0.0"
