"""Truthful application-artifact support declarations exposed to operators."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class ApplicationArtifactSupport:
    app_id: str
    display_name: str
    status: Literal["plaintext_parser", "interchange_parser", "detection_only"]
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
            status="plaintext_parser",
            maturity="experimental",
            native_parser_id="android.whatsapp.message",
            acquisition_requirements=filesystem_requirement,
            limitations=(
                "Non-rooted ADB cannot normally read the private application database.",
                "Encrypted backups and database variants are not decrypted.",
                "Only recognized plaintext message-table schemas are parsed.",
            ),
        ),
        ApplicationArtifactSupport(
            app_id="telegram",
            display_name="Telegram",
            status="plaintext_parser",
            maturity="experimental",
            native_parser_id="android.telegram.messages",
            acquisition_requirements=filesystem_requirement,
            limitations=(
                "Telegram binary message blobs are not decoded by the native adapter.",
                "Secret chats and server-side content are not acquired or bypassed.",
            ),
        ),
        ApplicationArtifactSupport(
            app_id="signal",
            display_name="Signal",
            status="detection_only",
            maturity="experimental",
            native_parser_id=None,
            acquisition_requirements=filesystem_requirement,
            limitations=(
                "Signal databases are commonly SQLCipher-encrypted.",
                "ForensiX detects opaque input but does not extract keys or bypass encryption.",
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
