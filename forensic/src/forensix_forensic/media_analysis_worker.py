"""Isolated, bounded media-analysis worker.

Like ``preview_worker``, this module has no ForensiX application imports. The parent
launches it in Python isolated mode with fixed arguments and a deadline. It reads a
single hash-verified sealed object and emits a small JSON document describing the
media: perceptual hash, an EXIF allowlist (capture time, camera, GPS), optional OCR
text, and heuristic content-classification labels. It never mutates the source and
never emits embedded blobs or thumbnails.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError

WORKER_VERSION = "1.0.0"
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
HEADER_BYTES = 64
MAX_EXIF_TAGS = 64
MAX_EXIF_VALUE_CHARS = 256
MAX_OCR_CHARS = 20_000
PHASH_EDGE = 9  # difference hash uses a (PHASH_EDGE-1) x (PHASH_EDGE-1) = 8x8 grid -> 64 bits.
SUPPORTED_RASTER_MIMES = frozenset({"image/gif", "image/jpeg", "image/png", "image/webp"})
SAFE_EXIF_TAGS = frozenset(
    {
        "DateTime",
        "DateTimeDigitized",
        "DateTimeOriginal",
        "ExposureTime",
        "FNumber",
        "FocalLength",
        "ISOSpeedRatings",
        "LensModel",
        "Make",
        "Model",
        "Orientation",
        "Software",
    }
)

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
warnings.simplefilter("error", Image.DecompressionBombWarning)


class MediaAnalysisRejectedError(RuntimeError):
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
    return "application/octet-stream"


def _bounded_scalar(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_EXIF_VALUE_CHARS]


def _gps_coordinate(values: Any, reference: Any) -> float | None:
    try:
        degrees, minutes, seconds = (float(item) for item in values[:3])
        coordinate = degrees + minutes / 60 + seconds / 3600
        if str(reference).upper() in {"S", "W"}:
            coordinate = -coordinate
        return round(coordinate, 5)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_exif(image: Image.Image) -> dict[str, Any]:
    """Return a small JSON-safe EXIF allowlist plus GPS presence and coordinates."""
    result: dict[str, Any] = {"gps_present": False}
    try:
        exif = image.getexif()
    except (AttributeError, OSError, ValueError):
        return result
    safe_exif: dict[str, Any] = {}
    for tag_id, value in list(exif.items())[:MAX_EXIF_TAGS]:
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if tag_name in SAFE_EXIF_TAGS:
            safe_exif[tag_name] = _bounded_scalar(value)
    if safe_exif:
        result["exif"] = safe_exif
        result["camera_make"] = safe_exif.get("Make")
        result["camera_model"] = safe_exif.get("Model")
        result["captured_at_raw"] = safe_exif.get("DateTimeOriginal") or safe_exif.get("DateTime")
    try:
        gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        gps = {}
    if gps:
        latitude = _gps_coordinate(gps.get(2), gps.get(1))
        longitude = _gps_coordinate(gps.get(4), gps.get(3))
        result["gps_present"] = True
        if latitude is not None and longitude is not None:
            result["gps_latitude"] = latitude
            result["gps_longitude"] = longitude
    return result


def perceptual_hash(image: Image.Image) -> str:
    """Return a 64-bit difference hash as 16 lowercase hex characters.

    Difference hashing is orientation-agnostic to compression and small edits, so two
    near-identical images produce hashes with a small Hamming distance. It is a triage
    grouping aid, not a cryptographic identifier.
    """
    reduced = image.convert("L").resize((PHASH_EDGE, PHASH_EDGE - 1), Image.Resampling.LANCZOS)
    pixels = list(reduced.getdata())
    bits = 0
    index = 0
    for row in range(PHASH_EDGE - 1):
        row_start = row * PHASH_EDGE
        for col in range(PHASH_EDGE - 1):
            left = pixels[row_start + col]
            right = pixels[row_start + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
            index += 1
    return format(bits, f"0{index // 4}x")


def attempt_ocr(image: Image.Image) -> dict[str, Any]:
    """Attempt OCR only if a Tesseract engine is importable and installed.

    We never fabricate text. When no engine is present the status is ``unavailable``
    and no text is produced. This keeps the pipeline honest about its capabilities.
    """
    try:
        import pytesseract  # type: ignore[import-not-found]
    except Exception:
        return {"ocr_status": "unavailable", "ocr_engine": None, "ocr_text": None}
    try:
        text = pytesseract.image_to_string(image.convert("RGB"))
    except Exception:
        return {"ocr_status": "unavailable", "ocr_engine": "tesseract", "ocr_text": None}
    normalized = " ".join(text.split())[:MAX_OCR_CHARS]
    if not normalized:
        return {"ocr_status": "empty", "ocr_engine": "tesseract", "ocr_text": None}
    return {"ocr_status": "completed", "ocr_engine": "tesseract", "ocr_text": normalized}


def classify(image: Image.Image, exif: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce heuristic content-classification labels with explicit confidence.

    This is a transparent, explainable baseline, not a trained neural model. Each label
    records the signal it was derived from so an analyst can weigh it. Sensitive-content
    detectors (weapon/drug/explicit) require trained models that are not bundled; they
    are reported as ``unavailable`` rather than guessed.
    """
    width, height = image.size
    labels: list[dict[str, Any]] = []
    ratio = (width / height) if height else 0.0
    if exif.get("camera_make") or exif.get("camera_model"):
        labels.append(
            {
                "label": "camera_original",
                "confidence": 0.75,
                "basis": "exif_camera_tags_present",
            }
        )
    else:
        labels.append(
            {
                "label": "no_camera_metadata",
                "confidence": 0.5,
                "basis": "exif_camera_tags_absent",
            }
        )
    if exif.get("gps_present"):
        labels.append({"label": "geotagged", "confidence": 0.9, "basis": "exif_gps_ifd_present"})
    if ratio and (ratio >= 1.7 or ratio <= 0.6):
        labels.append(
            {
                "label": "likely_screenshot_or_panorama",
                "confidence": 0.4,
                "basis": f"aspect_ratio_{round(ratio, 2)}",
            }
        )
    labels.append(
        {
            "label": "sensitive_content_scan",
            "confidence": 0.0,
            "basis": "no_trained_model_bundled",
            "status": "unavailable",
        }
    )
    return labels


def analyze(source: Path) -> dict[str, Any]:
    if not source.is_file():
        raise MediaAnalysisRejectedError("SOURCE_NOT_REGULAR", "The source is not a regular file.")
    if source.stat().st_size > MAX_SOURCE_BYTES:
        raise MediaAnalysisRejectedError(
            "SOURCE_TOO_LARGE", "The source exceeds the bounded analysis input limit."
        )
    with source.open("rb") as stream:
        detected_mime = detect_mime(stream.read(HEADER_BYTES))
    if detected_mime not in SUPPORTED_RASTER_MIMES:
        raise MediaAnalysisRejectedError(
            "UNSUPPORTED_MEDIA_TYPE",
            "Only signature-validated JPEG, PNG, GIF, and WebP images can be analyzed.",
            detected_mime=detected_mime,
        )
    try:
        with Image.open(source) as image:
            decoded_mime = Image.MIME.get(image.format or "")
            if decoded_mime != detected_mime:
                raise MediaAnalysisRejectedError(
                    "DECODER_SIGNATURE_MISMATCH",
                    "The image decoder did not confirm the detected file signature.",
                    detected_mime=detected_mime,
                )
            image.seek(0)
            width, height = image.size
            if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
                raise MediaAnalysisRejectedError(
                    "PIXEL_LIMIT_EXCEEDED",
                    "The source image exceeds the pixel safety limit.",
                    detected_mime=detected_mime,
                )
            exif = extract_exif(image)
            image.load()
            phash = perceptual_hash(image)
            ocr = attempt_ocr(image)
            detections = classify(image, exif)
    except Image.DecompressionBombError as error:
        raise MediaAnalysisRejectedError(
            "PIXEL_LIMIT_EXCEEDED",
            "The source image exceeds the pixel safety limit.",
            detected_mime=detected_mime,
        ) from error
    except (UnidentifiedImageError, OSError, ValueError) as error:
        raise MediaAnalysisRejectedError(
            "IMAGE_DECODE_FAILED",
            "The image is corrupt, truncated, or unsupported.",
            detected_mime=detected_mime,
        ) from error
    return {
        "media_kind": "image",
        "detected_mime": detected_mime,
        "width": width,
        "height": height,
        "perceptual_hash": phash,
        "captured_at_raw": exif.get("captured_at_raw"),
        "camera_make": exif.get("camera_make"),
        "camera_model": exif.get("camera_model"),
        "gps_present": bool(exif.get("gps_present")),
        "gps_latitude": exif.get("gps_latitude"),
        "gps_longitude": exif.get("gps_longitude"),
        "exif": exif.get("exif", {}),
        "ocr_status": ocr["ocr_status"],
        "ocr_engine": ocr["ocr_engine"],
        "ocr_text": ocr["ocr_text"],
        "detections": detections,
        "detector_maturity": "heuristic",
        "worker_version": WORKER_VERSION,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated media-analysis worker.")
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        result = analyze(Path(args.source))
    except MediaAnalysisRejectedError as error:
        payload = {
            "status": "rejected",
            "code": error.code,
            "message": str(error),
            "detected_mime": error.detected_mime,
        }
        sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception:  # noqa: BLE001 - never leak internal detail to the parent
        payload = {
            "status": "failed",
            "code": "WORKER_UNEXPECTED_ERROR",
            "message": "The isolated media-analysis worker failed.",
        }
        sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return 0
    sys.stdout.write(
        json.dumps({"status": "analyzed", "result": result}, separators=(",", ":"), sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
