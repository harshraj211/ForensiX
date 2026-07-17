from pathlib import Path

import pytest
from PIL import Image

from forensix_forensic import preview_worker


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (b"\xff\xd8\xff\xe0", "image/jpeg"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"GIF89a", "image/gif"),
        (b"RIFF\x00\x00\x00\x00WEBP", "image/webp"),
        (b"%PDF-1.7", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"MZ\x90\x00", "application/vnd.microsoft.portable-executable"),
        (b"plain text", "application/octet-stream"),
    ],
)
def test_detect_mime_uses_bounded_magic_bytes(header: bytes, expected: str) -> None:
    assert preview_worker.detect_mime(header) == expected


def test_generate_reencodes_supported_image_and_strips_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source.png"
    output = tmp_path / "preview.png"
    image = Image.new("RGB", (1800, 900), color=(18, 72, 110))
    image.save(source, format="PNG", pnginfo=_metadata())

    result = preview_worker.generate(source, output)

    assert result["detected_mime"] == "image/png"
    assert result["width"] == 1024
    assert result["height"] == 512
    assert output.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    with Image.open(output) as derivative:
        assert "ForensiX-Test" not in derivative.info


def test_generate_rejects_truncated_image(tmp_path: Path) -> None:
    source = tmp_path / "truncated.png"
    source.write_bytes(b"\x89PNG\r\n\x1a\nnot-an-image")

    with pytest.raises(preview_worker.PreviewRejectedError) as raised:
        preview_worker.generate(source, tmp_path / "preview.png")

    assert raised.value.code == "IMAGE_DECODE_FAILED"
    assert not (tmp_path / "preview.png").exists()


def test_generate_rejects_unsupported_active_content(tmp_path: Path) -> None:
    source = tmp_path / "disguised.jpg"
    source.write_bytes(b"MZ\x90\x00hostile executable fixture")

    with pytest.raises(preview_worker.PreviewRejectedError) as raised:
        preview_worker.generate(source, tmp_path / "preview.png")

    assert raised.value.code == "UNSUPPORTED_MEDIA_TYPE"
    assert raised.value.detected_mime == "application/vnd.microsoft.portable-executable"


def test_generate_rejects_source_over_byte_limit(tmp_path: Path) -> None:
    source = tmp_path / "oversized.png"
    with source.open("wb") as stream:
        stream.seek(preview_worker.MAX_SOURCE_BYTES)
        stream.write(b"x")

    with pytest.raises(preview_worker.PreviewRejectedError) as raised:
        preview_worker.generate(source, tmp_path / "preview.png")

    assert raised.value.code == "SOURCE_TOO_LARGE"


def test_generate_rejects_decompression_bomb_before_pixel_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "many-pixels.png"
    Image.new("RGB", (10, 10), color=(1, 2, 3)).save(source, format="PNG")
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 4)

    with pytest.raises(preview_worker.PreviewRejectedError) as raised:
        preview_worker.generate(source, tmp_path / "preview.png")

    assert raised.value.code == "PIXEL_LIMIT_EXCEEDED"
    assert not (tmp_path / "preview.png").exists()


def _metadata():
    from PIL.PngImagePlugin import PngInfo

    metadata = PngInfo()
    metadata.add_text("ForensiX-Test", "must not survive derivative generation")
    return metadata
