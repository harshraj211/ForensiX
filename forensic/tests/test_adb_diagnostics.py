from forensix_forensic.adb.diagnostics import _missing_guidance, _transport_status


def test_transport_diagnostic_prioritizes_actionable_states() -> None:
    assert _transport_status({"authorized": 1, "offline": 1}) == "healthy"
    assert _transport_status({"unauthorized": 1}) == "authorization_required"
    assert _transport_status({"offline": 1}) == "offline"
    assert _transport_status({}) == "no_transports"
    assert _transport_status({"recovery": 1}) == "unsupported_transport"


def test_missing_diagnostic_is_platform_specific() -> None:
    assert "OEM USB driver" in " ".join(_missing_guidance("windows"))
    assert "udev" in " ".join(_missing_guidance("linux"))
    assert "Gatekeeper" in " ".join(_missing_guidance("darwin"))
