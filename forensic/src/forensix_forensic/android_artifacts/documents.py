"""Bounded parsers for sensitive Android Wi-Fi and Bluetooth configuration files."""

import configparser
import re
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml.ElementTree import fromstring

from forensix_forensic.evidence_io import (
    DocumentParserRegistry,
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
)

MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_XML_ELEMENTS = 20_000
MAX_XML_DEPTH = 64
MAX_TEXT_CHARACTERS = 2_000_000
MAX_BLUETOOTH_SECTIONS = 10_000
_BLUETOOTH_ADDRESS = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class AndroidDocumentParserError(ValueError):
    """Raised when a configuration file violates parser policy or schema."""


class AndroidWifiConfigParser:
    metadata = ParserMetadata(
        parser_id="android.wifi.config_store",
        name="Android Wi-Fi configuration",
        version="1.0.0",
        artifact_categories=("wifi",),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("WifiConfigStore.xml",),
    )

    def can_parse(self, source_locator: str) -> bool:
        return source_locator.casefold().endswith("wificonfigstore.xml")

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        root = _safe_xml_root(path)
        artifacts: list[ParsedArtifact] = []
        for ordinal, network in enumerate(root.iter("Network")):
            values = _named_xml_values(network)
            ssid = _unquote(values.get("SSID")) or "Unknown SSID"
            credential = values.get("PreSharedKey") or values.get("WEPKeys")
            metadata: dict[str, object] = {
                "application": "android_wifi",
                "ssid": ssid,
                "config_key": _unquote(values.get("ConfigKey")),
                "security_params": values.get("SecurityParamsList"),
                "credential_present": credential is not None,
            }
            if credential is not None:
                metadata["credential_sha256"] = sha256(credential.encode()).hexdigest()
            artifacts.append(
                ParsedArtifact(
                    category="system",
                    subtype="wifi_network",
                    title=f"Wi-Fi network: {ssid}",
                    summary="Saved Wi-Fi configuration; credential value withheld",
                    event_time=None,
                    source_locator=f"{context.input_locator}#Network:{ordinal}",
                    status="active",
                    confidence="medium",
                    metadata={key: value for key, value in metadata.items() if value is not None},
                )
            )
        return artifacts


class AndroidBluetoothConfigParser:
    metadata = ParserMetadata(
        parser_id="android.bluetooth.config",
        name="Android Bluetooth paired-device configuration",
        version="1.0.0",
        artifact_categories=("bluetooth",),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=("bt_config.conf",),
    )

    def can_parse(self, source_locator: str) -> bool:
        return source_locator.casefold().endswith("bt_config.conf")

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=True,
            empty_lines_in_values=False,
        )
        try:
            parser.read_string(_safe_text(path))
        except configparser.Error as error:
            raise AndroidDocumentParserError(
                "Bluetooth configuration syntax is unsupported."
            ) from error
        sections = [name for name in parser.sections() if _BLUETOOTH_ADDRESS.fullmatch(name)]
        if len(sections) > MAX_BLUETOOTH_SECTIONS:
            raise AndroidDocumentParserError("Bluetooth configuration exceeds the section limit.")
        artifacts: list[ParsedArtifact] = []
        for address in sections:
            values = dict(parser.items(address))
            link_key = values.pop("linkkey", None)
            metadata: dict[str, object] = {
                "application": "android_bluetooth",
                "address": address.upper(),
                "name": values.get("name"),
                "class": values.get("devclass") or values.get("class"),
                "device_type": values.get("devtype"),
                "link_key_present": link_key is not None,
            }
            if link_key is not None:
                metadata["link_key_sha256"] = sha256(link_key.encode()).hexdigest()
            artifacts.append(
                ParsedArtifact(
                    category="system",
                    subtype="bluetooth_device",
                    title=f"Bluetooth device: {values.get('name') or address.upper()}",
                    summary=f"Paired device {address.upper()}; link key value withheld",
                    event_time=_unix_seconds(values.get("timestamp")),
                    source_locator=f"{context.input_locator}#{address.upper()}",
                    status="active",
                    confidence="medium",
                    metadata={key: value for key, value in metadata.items() if value is not None},
                )
            )
        return artifacts


def android_document_parser_registry() -> DocumentParserRegistry:
    registry = DocumentParserRegistry()
    registry.register(AndroidWifiConfigParser())
    registry.register(AndroidBluetoothConfigParser())
    return registry


def _safe_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AndroidDocumentParserError("The document source must be a regular non-link file.")
    size = path.stat().st_size
    if size < 1 or size > MAX_DOCUMENT_BYTES:
        raise AndroidDocumentParserError("The document source violates the size limit.")
    return path.read_bytes()


def _safe_text(path: Path) -> str:
    payload = _safe_bytes(path)
    if b"\x00" in payload:
        raise AndroidDocumentParserError("The configuration is not bounded UTF-8 text.")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AndroidDocumentParserError("The configuration is not valid UTF-8 text.") from error


def _safe_xml_root(path: Path) -> Element:
    payload = _safe_bytes(path)
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise AndroidDocumentParserError("DTD and entity declarations are prohibited.")
    try:
        root = fromstring(payload)
    except ParseError as error:
        raise AndroidDocumentParserError("The XML configuration is malformed.") from error
    element_count = 0
    text_characters = 0
    stack: list[tuple[Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        element_count += 1
        text_characters += len(element.text or "") + len(element.tail or "")
        if element_count > MAX_XML_ELEMENTS or depth > MAX_XML_DEPTH:
            raise AndroidDocumentParserError("The XML structure exceeds parser limits.")
        if text_characters > MAX_TEXT_CHARACTERS:
            raise AndroidDocumentParserError("The XML text exceeds parser limits.")
        stack.extend((child, depth + 1) for child in element)
    return root


def _named_xml_values(element: Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for child in element.iter():
        name = child.attrib.get("name")
        if name and child.text and len(name) <= 128 and len(child.text) <= 16_384:
            values[name] = child.text.strip()
    return values


def _unquote(value: str | None) -> str | None:
    if value is None:
        return None
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value


def _unix_seconds(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromtimestamp(int(value), tz=UTC)
    except (OverflowError, ValueError):
        return None
    return parsed if 1990 <= parsed.year <= 2200 else None
