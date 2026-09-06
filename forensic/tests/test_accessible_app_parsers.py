from forensix_forensic.android_artifacts import (
    AccessibleAppArtifactJSONParser,
    WhatsAppBackupArtifactParser,
    android_parser_registry,
)
from forensix_forensic.evidence_io import ParserContext


def _context(locator: str = "test/path") -> ParserContext:
    return ParserContext(
        case_id="case",
        evidence_source_id="source",
        working_copy_id="copy",
        source_sha256="0" * 64,
        source_label=locator,
        input_locator=locator,
        input_sha256="1" * 64,
    )


def test_whatsapp_backup_artifact_parser_header_detection() -> None:
    parser = WhatsAppBackupArtifactParser()

    assert parser.can_parse_file("msgstore.db.crypt14") is True
    assert parser.can_parse_file("msgstore.db.crypt12") is True
    assert parser.can_parse_file("wa.db") is True
    assert parser.can_parse_file("other.txt") is False

    art14 = parser.parse_backup_file(
        file_name="msgstore.db.crypt14",
        size_bytes=1048576,
        context=_context("sdcard/WhatsApp/Databases/msgstore.db.crypt14"),
        header_bytes=b"crypt14_header_data_bytes",
    )

    assert art14.category == "communication"
    assert art14.subtype == "whatsapp_backup_artifact"
    assert "crypt14" in art14.title
    assert art14.metadata["backup_version"] == "crypt14"
    assert art14.metadata["size_bytes"] == 1048576
    assert art14.metadata["has_header_bytes"] is True


def test_accessible_app_artifact_json_parser() -> None:
    parser = AccessibleAppArtifactJSONParser()
    context = _context("sdcard/forensix_out/app_artifacts.json")

    json_data = [
        {
            "package_name": "com.whatsapp",
            "artifact_category": "backup",
            "relative_path": "WhatsApp/Databases/msgstore.db.crypt14",
            "size_bytes": 2048576,
            "mime_type": "application/octet-stream",
            "accessibility_status": "accessible",
        },
        {
            "package_name": "org.telegram.messenger",
            "artifact_category": "media",
            "relative_path": "Telegram/Telegram Audio/audio_1.ogg",
            "size_bytes": 51200,
            "mime_type": "audio/ogg",
            "accessibility_status": "accessible",
        },
    ]

    artifacts = parser.parse_json_data(json_data, context)

    assert len(artifacts) == 2

    wa_art = artifacts[0]
    assert wa_art.category == "communication"
    assert "com.whatsapp" in wa_art.title
    assert wa_art.metadata["package_name"] == "com.whatsapp"
    assert wa_art.metadata["size_bytes"] == 2048576

    tg_art = artifacts[1]
    assert tg_art.category == "communication"
    assert "org.telegram.messenger" in tg_art.title
    assert tg_art.metadata["mime_type"] == "audio/ogg"


def test_registry_contains_new_parsers() -> None:
    registry = android_parser_registry()
    parser_ids = set(registry._parsers.keys())

    assert "android.whatsapp.backup_artifact" in parser_ids
    assert "android.agent.app_artifacts" in parser_ids
