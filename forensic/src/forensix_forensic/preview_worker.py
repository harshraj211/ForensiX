"""Isolated, bounded MIME inspection and raster thumbnail worker.

This module deliberately has no ForensiX application imports. The parent launches this
file with Python isolated mode, fixed arguments, a deadline, and a contained output path.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError

WORKER_VERSION = "1.0.0"
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
MAX_THUMBNAIL_EDGE = 1024
HEADER_BYTES = 64
SUPPORTED_RASTER_MIMES = frozenset({"image/gif", "image/jpeg", "image/png", "image/webp"})

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
warnings.simplefilter("error", Image.DecompressionBombWarning)


class PreviewRejectedError(RuntimeError):
    """A stable, safe rejection intended for the parent process."""

    def __init__(self, code: str, message: str, *, detected_mime: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.detected_mime = detected_mime


def detect_mime(header: bytes) -> str:
    """Return a conservative MIME label from bounded magic bytes."""
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image/webp"
    if header.startswith(b"%PDF-"):
        return "application/pdf"
    if header.startswith(b"PK\x03\x04"):
        return "application/zip"
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    if header.startswith(b"Rar!\x1a\x07"):
        return "application/vnd.rar"
    if header.startswith(b"\x1f\x8b\x08"):
        return "application/gzip"
    if header.startswith(b"MZ"):
        return "application/vnd.microsoft.portable-executable"
    if header.startswith(b"\x7fELF"):
        return "application/x-elf"
    return "application/octet-stream"


def generate(source: Path, output: Path) -> dict[str, Any]:
    source_stat = source.stat()
    if not source.is_file():
        raise PreviewRejectedError("SOURCE_NOT_REGULAR", "The source is not a regular file.")
    if source_stat.st_size > MAX_SOURCE_BYTES:
        raise PreviewRejectedError(
            "SOURCE_TOO_LARGE", "The source exceeds the bounded preview input limit."
        )
    with source.open("rb") as stream:
        detected_mime = detect_mime(stream.read(HEADER_BYTES))
    if detected_mime not in SUPPORTED_RASTER_MIMES:
        raise PreviewRejectedError(
            "UNSUPPORTED_MEDIA_TYPE",
            "Only signature-validated JPEG, PNG, GIF, and WebP images can be previewed.",
            detected_mime=detected_mime,
        )

    try:
        with Image.open(source) as image:
            decoded_mime = Image.MIME.get(image.format or "")
            if decoded_mime != detected_mime:
                raise PreviewRejectedError(
                    "DECODER_SIGNATURE_MISMATCH",
                    "The image decoder did not confirm the detected file signature.",
                    detected_mime=detected_mime,
                )
            image.seek(0)
            width, height = image.size
            if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
                raise PreviewRejectedError(
                    "PIXEL_LIMIT_EXCEEDED",
                    "The source image exceeds the pixel safety limit.",
                    detected_mime=detected_mime,
                )
            image.load()
            image.thumbnail((MAX_THUMBNAIL_EDGE, MAX_THUMBNAIL_EDGE), Image.Resampling.LANCZOS)
            rendered = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            rendered.save(output, format="PNG", optimize=False)
            output_width, output_height = rendered.size
    except Image.DecompressionBombError as error:
        raise PreviewRejectedError(
            "PIXEL_LIMIT_EXCEEDED",
            "The source image exceeds the pixel safety limit.",
            detected_mime=detected_mime,
        ) from error
    except (UnidentifiedImageError, OSError, ValueError) as error:
        raise PreviewRejectedError(
            "IMAGE_DECODE_FAILED",
            "The image is corrupt, truncated, or unsupported.",
            detected_mime=detected_mime,
        ) from error

    output_size = output.stat().st_size
    if output_size < 1 or output_size > MAX_OUTPUT_BYTES:
        output.unlink(missing_ok=True)
        raise PreviewRejectedError(
            "OUTPUT_LIMIT_EXCEEDED", "The generated preview exceeds the output safety limit."
        )
    with output.open("rb") as stream:
        if stream.read(8) != b"\x89PNG\r\n\x1a\n":
            output.unlink(missing_ok=True)
            raise PreviewRejectedError(
                "OUTPUT_VALIDATION_FAILED", "The generated derivative is not a valid PNG."
            )
    return {
        "detected_mime": detected_mime,
        "height": output_height,
        "output_mime": "image/png",
        "source_height": height,
        "source_width": width,
        "width": output_width,
        "worker_version": WORKER_VERSION,
    }


def _apply_posix_limits() -> None:
    if os.name == "nt":
        return
    try:
        import resource

        resource.setrlimit(  # type: ignore[attr-defined]
            resource.RLIMIT_AS,  # type: ignore[attr-defined]
            (512 * 1024 * 1024, 512 * 1024 * 1024),
        )
        resource.setrlimit(  # type: ignore[attr-defined]
            resource.RLIMIT_CPU,  # type: ignore[attr-defined]
            (4, 4),
        )
        resource.setrlimit(  # type: ignore[attr-defined]
            resource.RLIMIT_FSIZE,  # type: ignore[attr-defined]
            (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES),
        )
    except (ImportError, OSError, ValueError):
        # The parent still enforces wall-clock, source, and output limits.
        return


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    _apply_posix_limits()
    output = Path(arguments.output)
    try:
        result = generate(Path(arguments.source), output)
    except PreviewRejectedError as error:
        output.unlink(missing_ok=True)
        print(
            json.dumps(
                {
                    "code": error.code,
                    "detected_mime": error.detected_mime or "application/octet-stream",
                    "message": str(error),
                    "status": "rejected",
                }
            )
        )
        return 2
    except Exception:
        output.unlink(missing_ok=True)
        print(
            json.dumps(
                {
                    "code": "WORKER_FAILED",
                    "message": "The isolated preview worker failed safely.",
                    "status": "failed",
                }
            )
        )
        return 1
    print(json.dumps({"result": result, "status": "available"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
