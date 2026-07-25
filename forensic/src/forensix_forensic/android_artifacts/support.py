"""Truthful application-artifact support declarations exposed to operators."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class ApplicationArtifactSupport:
    app_id: str
    display_name: str
    status: Literal[
        "plaintext_parser",
        "interchange_parser",
        "detection_only",
        "extraction_available",
    ]
    maturity: Literal["experimental", "validated"]
    native_parser_id: str | None
    acquisition_requirements: tuple[str, ...]
    limitations: tuple[str, ...]


def application_artifact_support() -> tuple[ApplicationArtifactSupport, ...]:
    filesystem_requirement = (
        "A lawfully acquired plaintext database from a rooted capture, compatible backup, "
        "or investigator import is required.",
    )
    return (
        ApplicationArtifactSupport(
            app_id="whatsapp",
            display_name="WhatsApp",
            status="extraction_available",
            maturity="experimental",
            native_parser_id="android.whatsapp.message",
            acquisition_requirements=(
                "A rooted device enables direct database extraction via the rooted bundle. "
                "A non-rooted device is supported via the downgrade-attack workflow: "
                "the tool temporarily downgrades WhatsApp to a version that permits "
                "ADB backup, captures the backup, then restores the current version.",
            ),
            limitations=(
                "The downgrade-attack requires a pre-staged vulnerable APK (v2.11.431).",
                "ADB backup requires the operator to approve on the device screen.",
                "Encrypted backup keys may not be recoverable for all WhatsApp versions.",
                "Database decryption is best-effort for crypt15 and may fail on newer schemas.",
                "Deleted-message carving is heuristic and may produce false positives.",
            ),
        ),
        ApplicationArtifactSupport(
            app_id="telegram",
            display_name="Telegram",
            status="extraction_available",
            maturity="experimental",
            native_parser_id="android.telegram.messages",
            acquisition_requirements=filesystem_requirement,
            limitations=(
                "Telegram extraction on non-rooted devices is not supported.",
                "Telegram binary message blobs are not decoded by the native adapter.",
                "Secret chats and server-side content are not acquired or bypassed.",
                "Direct sandbox access via root is required.",
            ),
        ),
        ApplicationArtifactSupport(
            app_id="signal",
            display_name="Signal",
            status="extraction_available",
            maturity="experimental",
            native_parser_id=None,
            acquisition_requirements=filesystem_requirement,
            limitations=(
                "Signal extraction requires a rooted device for SQLCipher key retrieval.",
                "The extraction key is read from shared_prefs in the app sandbox.",
                "SQLCipher decryption is best-effort and may fail on newer cipher versions.",
                "Signal databases use SQLCipher 4 with a passphrase; "
                "older versions used a different key derivation.",
            ),
        ),
        *(
            ApplicationArtifactSupport(
                app_id=app_id,
                display_name=display_name,
                status="interchange_parser",
                maturity="experimental",
                native_parser_id=f"android.{app_id}.messages",
                acquisition_requirements=filesystem_requirement,
                limitations=(
                    "Only the documented ForensiX plaintext interchange schema is supported.",
                    "Current production application schemas vary and are not claimed as universal.",
                ),
            )
            for app_id, display_name in (
                ("messenger", "Messenger"),
                ("facebook", "Facebook"),
                ("instagram", "Instagram"),
            )
        ),
        ApplicationArtifactSupport(
            app_id="snapchat",
            display_name="Snapchat",
            status="detection_only",
            maturity="experimental",
            native_parser_id=None,
            acquisition_requirements=filesystem_requirement,
            limitations=(
                "No production-validated native Snapchat content parser is included.",
                "Ephemeral or server-side content cannot be reconstructed from ordinary ADB.",
            ),
        ),
    )
