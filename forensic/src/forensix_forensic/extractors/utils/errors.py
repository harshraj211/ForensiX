class ForensicExtractorError(Exception):
    """Base class for all forensic extractor exceptions."""

    pass


class AdbCommandError(ForensicExtractorError):
    """Raised when an ADB command fails or times out."""

    pass


class DeviceNotConnectedError(AdbCommandError):
    """Raised when the target device is disconnected."""

    pass


class AccessDeniedError(ForensicExtractorError):
    """Raised when the operation requires root or higher privileges."""

    pass


class ArtifactNotFoundError(ForensicExtractorError):
    """Raised when a required file or artifact is missing on the device."""

    pass


class DecryptionError(ForensicExtractorError):
    """Raised when cryptographic decryption fails (e.g. invalid key or MAC)."""

    pass


class ParseError(ForensicExtractorError):
    """Raised when parsing output or files fails."""

    pass
