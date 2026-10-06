"""Signature findings must be backed by actual decodable source bytes."""

from hashlib import sha256
from io import BytesIO
from pathlib import Path

from PIL import Image

from forensix_forensic.extractors.raw_disk_carver import RawDiskCarver


def test_carver_skips_false_signatures_and_hashes_exact_jpeg(tmp_path: Path) -> None:
    output = BytesIO()
    Image.new("RGB", (12, 12), "blue").save(output, format="JPEG")
    jpeg = output.getvalue()
    prefix = b"\xff\xd8\xffnot-a-jpeg\xff\xd9" + b"\0" * 32
    image = tmp_path / "source.img"
    image.write_bytes(prefix + jpeg + b"\0" * 10)

    result = RawDiskCarver().carve_image(image)

    assert result.total_carved_files == 1
    assert result.scanned_bytes == image.stat().st_size
    assert result.truncated is False
    assert result.carved_media_items[0].file_type == "jpeg"
    assert result.carved_media_items[0].offset_bytes == len(prefix)
    assert result.carved_media_items[0].size_bytes == len(jpeg)
    assert result.carved_media_items[0].sha256_hash == sha256(jpeg).hexdigest()
