"""Optional local ML adapters for ForensiX media analysis.

This module is intentionally dependency tolerant. Heavy model runtimes are loaded only
when the examiner has installed them and provided model paths through environment
variables. When a runtime or model is absent the caller gets explicit unavailable
labels instead of fabricated detections.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any, cast

from PIL import Image

FACE_CASCADE_ENV = "FORENSIX_FACE_CASCADE"
FACE_EMBEDDING_ONNX_ENV = "FORENSIX_FACE_EMBEDDING_ONNX_MODEL"
FACE_EMBEDDING_INPUT_SIZE_ENV = "FORENSIX_FACE_EMBEDDING_INPUT_SIZE"
IMAGE_EMBEDDING_ONNX_ENV = "FORENSIX_IMAGE_EMBEDDING_ONNX_MODEL"
IMAGE_EMBEDDING_INPUT_SIZE_ENV = "FORENSIX_IMAGE_EMBEDDING_INPUT_SIZE"
IMAGE_EMBEDDING_PREPROCESS_ENV = "FORENSIX_IMAGE_EMBEDDING_PREPROCESS"
OBJECT_ONNX_ENV = "FORENSIX_OBJECT_ONNX_MODEL"
OBJECT_LABELS_ENV = "FORENSIX_OBJECT_LABELS"
OBJECT_INPUT_SIZE_ENV = "FORENSIX_OBJECT_INPUT_SIZE"
OBJECT_SCORE_THRESHOLD_ENV = "FORENSIX_OBJECT_SCORE_THRESHOLD"
WHISPER_MODEL_ENV = "FORENSIX_WHISPER_MODEL"
MAX_OBJECT_LABELS = 8
MAX_TRANSCRIPT_CHARS = 40_000
MAX_TRANSCRIPT_SEGMENTS = 200
DEFAULT_OBJECT_INPUT_SIZE = 224
DEFAULT_FACE_EMBEDDING_INPUT_SIZE = 112
DEFAULT_IMAGE_EMBEDDING_INPUT_SIZE = 224
DEFAULT_OBJECT_SCORE_THRESHOLD = 0.20


def image_model_detections(image: Image.Image) -> list[dict[str, Any]]:
    """Return local ML detections for an image when configured.

    Face detection uses OpenCV's Haar cascade when OpenCV is installed. Face
    regions can carry embeddings from a configured ONNX face model. Object
    analysis uses a generic ONNX adapter: detector-shaped outputs produce
    YOLO/SSD-style regions, while simple class vectors produce image labels.
    Unsupported runtimes return explicit unavailable labels.
    """
    detections: list[dict[str, Any]] = []
    embedding = _image_embedding_onnx(image)
    if embedding is not None:
        detections.append(embedding)
    detections.extend(_detect_faces_opencv(image))
    detections.extend(_classify_objects_onnx(image))
    return detections


def speech_adapter_status() -> dict[str, Any]:
    """Return the configured speech adapter state for audio/video artifacts."""
    model = os.environ.get(WHISPER_MODEL_ENV)
    if not model:
        return {
            "label": "speech_transcription_model_not_configured",
            "confidence": 1.0,
            "basis": f"{WHISPER_MODEL_ENV}_absent",
            "status": "unavailable",
        }
    model_path = Path(model)
    if not model_path.exists():
        return {
            "label": "speech_transcription_model_missing",
            "confidence": 1.0,
            "basis": str(model_path),
            "status": "unavailable",
        }
    runtime = _speech_runtime_name()
    if runtime is None:
        return {
            "label": "speech_transcription_runtime_missing",
            "confidence": 1.0,
            "basis": "install faster-whisper or openai-whisper",
            "status": "unavailable",
        }
    return {
        "label": "speech_transcription_model_configured",
        "confidence": 1.0,
        "basis": f"{runtime}:{model_path}",
        "status": "available",
    }


def transcribe_media(source: Path, media_kind: str, detected_mime: str | None) -> dict[str, Any]:
    """Transcribe audio/video with a configured local Whisper runtime."""
    status = speech_adapter_status()
    if status.get("status") != "available":
        return _speech_payload(media_kind, detected_mime, [status], None, "not_attempted")

    model = str(Path(cast(str, os.environ.get(WHISPER_MODEL_ENV))))
    try:
        import faster_whisper  # type: ignore[import-not-found]

        whisper_model = faster_whisper.WhisperModel(model, device="cpu", compute_type="int8")
        segments_iter, info = whisper_model.transcribe(str(source), vad_filter=True)
        segments: list[dict[str, Any]] = []
        text_parts: list[str] = []
        for index, segment in enumerate(segments_iter):
            if index >= MAX_TRANSCRIPT_SEGMENTS:
                break
            segment_text = str(segment.text).strip()
            if segment_text:
                text_parts.append(segment_text)
            segments.append(
                {
                    "start": round(float(segment.start), 3),
                    "end": round(float(segment.end), 3),
                    "text": segment_text[:1000],
                }
            )
        transcript = " ".join(text_parts).strip()[:MAX_TRANSCRIPT_CHARS]
        detections = [
            {
                "label": "speech_transcription_completed" if transcript else "speech_not_detected",
                "confidence": 0.85 if transcript else 0.55,
                "basis": f"faster_whisper:{model}",
                "status": "completed",
                "details": {
                    "language": getattr(info, "language", None),
                    "duration": _float_or_none(getattr(info, "duration", None)),
                    "segment_count": len(segments),
                    "segments": segments,
                },
            }
        ]
        return _speech_payload(
            media_kind,
            detected_mime,
            detections,
            transcript or None,
            "completed" if transcript else "empty",
            engine="faster-whisper",
        )
    except Exception as faster_error:
        try:
            import whisper  # type: ignore[import-not-found]

            model_obj = whisper.load_model(model)
            result = model_obj.transcribe(str(source))
            transcript = str(result.get("text", "")).strip()[:MAX_TRANSCRIPT_CHARS]
            raw_segments = result.get("segments", [])
            segments = [
                {
                    "start": round(float(item.get("start", 0.0)), 3),
                    "end": round(float(item.get("end", 0.0)), 3),
                    "text": str(item.get("text", "")).strip()[:1000],
                }
                for item in raw_segments[:MAX_TRANSCRIPT_SEGMENTS]
                if isinstance(item, dict)
            ]
            detections = [
                {
                    "label": "speech_transcription_completed"
                    if transcript
                    else "speech_not_detected",
                    "confidence": 0.85 if transcript else 0.55,
                    "basis": f"openai_whisper:{model}",
                    "status": "completed",
                    "details": {
                        "language": result.get("language"),
                        "segment_count": len(segments),
                        "segments": segments,
                    },
                }
            ]
            return _speech_payload(
                media_kind,
                detected_mime,
                detections,
                transcript or None,
                "completed" if transcript else "empty",
                engine="whisper",
            )
        except Exception as whisper_error:
            return _speech_payload(
                media_kind,
                detected_mime,
                [
                    {
                        "label": "speech_transcription_failed",
                        "confidence": 1.0,
                        "basis": f"faster_whisper:{type(faster_error).__name__}; whisper:{type(whisper_error).__name__}",
                        "status": "failed",
                    }
                ],
                None,
                "unavailable",
            )


def _detect_faces_opencv(image: Image.Image) -> list[dict[str, Any]]:
    try:
        import cv2
        import numpy as np
    except Exception:
        return [
            {
                "label": "face_detection_runtime_missing",
                "confidence": 1.0,
                "basis": "install opencv-python for local face detection",
                "status": "unavailable",
            }
        ]

    try:
        cascade_path = os.environ.get(FACE_CASCADE_ENV)
        if cascade_path is None:
            cascade_path = str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml")
    except Exception:
        return [
            {
                "label": "face_detection_runtime_missing",
                "confidence": 1.0,
                "basis": "opencv runtime does not expose cascade metadata",
                "status": "unavailable",
            }
        ]
    if not Path(cascade_path).exists():
        return [
            {
                "label": "face_detection_model_missing",
                "confidence": 1.0,
                "basis": cascade_path,
                "status": "unavailable",
            }
        ]

    try:
        rgb = image.convert("RGB")
        gray = cv2.cvtColor(np.array(rgb), cv2.COLOR_RGB2GRAY)
        detector = cv2.CascadeClassifier(cascade_path)
        faces = detector.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(24, 24))
    except Exception:
        return [
            {
                "label": "face_detection_runtime_missing",
                "confidence": 1.0,
                "basis": "opencv runtime is incomplete or incompatible",
                "status": "unavailable",
            }
        ]
    count = int(len(faces))
    if count == 0:
        return [
            {
                "label": "face_not_detected",
                "confidence": 0.65,
                "basis": "opencv_haar_frontalface_default",
                "status": "completed",
            }
        ]
    width, height = rgb.size
    detections = [
        {
            "label": "face_detected",
            "confidence": 0.78,
            "basis": f"opencv_haar_frontalface_default_count_{count}",
            "status": "completed",
            "details": {"face_count": count},
        }
    ]
    for index, (x, y, w, h) in enumerate(faces[:20]):
        region = _region(float(x), float(y), float(w), float(h), width, height)
        details: dict[str, Any] = {"index": index}
        embedding = _face_embedding_for_region(rgb, region)
        if embedding is not None:
            details.update(embedding)
        detections.append(
            {
                "label": "face_region",
                "confidence": 0.78,
                "basis": "opencv_haar_frontalface_default",
                "status": "completed",
                "region": region,
                "details": details,
            }
        )
    return detections


def _classify_objects_onnx(image: Image.Image) -> list[dict[str, Any]]:
    model = os.environ.get(OBJECT_ONNX_ENV)
    if not model:
        return [
            {
                "label": "object_detection_model_not_configured",
                "confidence": 1.0,
                "basis": f"{OBJECT_ONNX_ENV}_absent",
                "status": "unavailable",
            }
        ]
    model_path = Path(model)
    if not model_path.exists():
        return [
            {
                "label": "object_detection_model_missing",
                "confidence": 1.0,
                "basis": str(model_path),
                "status": "unavailable",
            }
        ]
    try:
        import numpy as np
        import onnxruntime as ort
    except Exception:
        return [
            {
                "label": "object_detection_runtime_missing",
                "confidence": 1.0,
                "basis": "install onnxruntime for local object detection",
                "status": "unavailable",
            }
        ]

    labels_path = os.environ.get(OBJECT_LABELS_ENV)
    labels = _read_labels(labels_path) if labels_path else []
    size = _int_env(OBJECT_INPUT_SIZE_ENV, DEFAULT_OBJECT_INPUT_SIZE)
    threshold = _float_env(OBJECT_SCORE_THRESHOLD_ENV, DEFAULT_OBJECT_SCORE_THRESHOLD)
    try:
        outputs = _run_onnx_outputs(model_path, _image_to_nchw(image, size, np), np, ort)
        boxed = _object_regions_from_outputs(
            outputs, labels, threshold, str(model_path), image.size, np
        )
        if boxed:
            return boxed
        scores = _flatten_scores(outputs[0], np)
        top = _top_scores(scores, threshold, MAX_OBJECT_LABELS)
    except Exception as error:
        return [
            {
                "label": "object_detection_failed",
                "confidence": 1.0,
                "basis": type(error).__name__,
                "status": "failed",
            }
        ]

    if not top:
        return [
            {
                "label": "object_not_detected",
                "confidence": 0.55,
                "basis": str(model_path),
                "status": "completed",
            }
        ]
    return [
        {
            "label": f"object_{_safe_label(labels[index] if index < len(labels) else str(index))}",
            "confidence": round(score, 4),
            "basis": str(model_path),
            "status": "completed",
            "details": {"class_index": index, "output_format": "classification"},
        }
        for index, score in top
    ]


def _image_embedding_onnx(image: Image.Image) -> dict[str, Any] | None:
    model = os.environ.get(IMAGE_EMBEDDING_ONNX_ENV)
    if not model:
        return None
    model_path = Path(model)
    if not model_path.exists():
        return {
            "label": "image_embedding_model_missing",
            "confidence": 1.0,
            "basis": str(model_path),
            "status": "unavailable",
        }
    try:
        import numpy as np
        import onnxruntime as ort
    except Exception:
        return {
            "label": "image_embedding_runtime_missing",
            "confidence": 1.0,
            "basis": "install onnxruntime for local image embeddings",
            "status": "unavailable",
        }
    size = _int_env(IMAGE_EMBEDDING_INPUT_SIZE_ENV, DEFAULT_IMAGE_EMBEDDING_INPUT_SIZE)
    try:
        outputs = _run_onnx_outputs(model_path, _image_embedding_input(image, size, np), np, ort)
        vector = _embedding_vector(outputs[0], np)
    except Exception as error:
        return {
            "label": "image_embedding_failed",
            "confidence": 1.0,
            "basis": type(error).__name__,
            "status": "failed",
        }
    if not vector:
        return {
            "label": "image_embedding_empty",
            "confidence": 0.55,
            "basis": str(model_path),
            "status": "completed",
        }
    return {
        "label": "image_embedding",
        "confidence": 1.0,
        "basis": str(model_path),
        "status": "completed",
        "details": {
            "embedding_model": str(model_path),
            "embedding": vector[:512],
            "embedding_dimensions": min(len(vector), 512),
            "embedding_family": "clip_style_onnx",
            "preprocessing": _image_embedding_preprocess_name(),
        },
    }


def _face_embedding_for_region(
    image: Image.Image, region: dict[str, float]
) -> dict[str, Any] | None:
    model = os.environ.get(FACE_EMBEDDING_ONNX_ENV)
    if not model:
        return None
    model_path = Path(model)
    if not model_path.exists():
        return {
            "embedding_status": "unavailable",
            "embedding_model": str(model_path),
            "embedding_error": "face_embedding_model_missing",
        }
    try:
        import numpy as np
        import onnxruntime as ort
    except Exception:
        return {
            "embedding_status": "unavailable",
            "embedding_model": str(model_path),
            "embedding_error": "face_embedding_runtime_missing",
        }

    size = _int_env(FACE_EMBEDDING_INPUT_SIZE_ENV, DEFAULT_FACE_EMBEDDING_INPUT_SIZE)
    try:
        face_crop = _crop_region(image, region)
        outputs = _run_onnx_outputs(model_path, _image_to_nchw(face_crop, size, np), np, ort)
        vector = _embedding_vector(outputs[0], np)
    except Exception as error:
        return {
            "embedding_status": "failed",
            "embedding_model": str(model_path),
            "embedding_error": type(error).__name__,
        }
    if not vector:
        return {
            "embedding_status": "failed",
            "embedding_model": str(model_path),
            "embedding_error": "empty_embedding",
        }
    return {
        "embedding_status": "completed",
        "embedding_model": str(model_path),
        "embedding": vector[:128],
        "embedding_dimensions": min(len(vector), 128),
    }


def _run_onnx_outputs(model_path: Path, tensor: Any, np: Any, ort: Any) -> list[Any]:
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    input_meta = session.get_inputs()[0]
    return cast(list[Any], session.run(None, {input_meta.name: tensor}))


def _object_regions_from_outputs(
    outputs: list[Any],
    labels: list[str],
    threshold: float,
    model_basis: str,
    image_size: tuple[int, int],
    np: Any,
) -> list[dict[str, Any]]:
    rows = _detector_rows(outputs, np)
    detections: list[dict[str, Any]] = []
    for row in rows:
        parsed = _parse_detector_row(row, labels, threshold, image_size)
        if parsed is None:
            continue
        detections.append(
            {
                "label": f"object_{_safe_label(parsed['label'])}",
                "confidence": parsed["score"],
                "basis": model_basis,
                "status": "completed",
                "region": parsed["region"],
                "details": {
                    "class_index": parsed["class_index"],
                    "output_format": parsed["output_format"],
                },
            }
        )
        if len(detections) >= MAX_OBJECT_LABELS:
            break
    if len(detections) == 0:
        return []
    detections.sort(key=lambda item: float(item["confidence"]), reverse=True)
    return detections


def _detector_rows(outputs: list[Any], np: Any) -> list[list[float]]:
    if not outputs:
        return []
    array = np.asarray(outputs[0]).astype("float32")
    if getattr(array, "ndim", 0) == 3 and array.shape[0] == 1:
        array = array[0]
    if getattr(array, "ndim", 0) == 3 and array.shape[-1] >= 6:
        array = array.reshape((-1, array.shape[-1]))
    if getattr(array, "ndim", 0) != 2:
        return []
    if array.shape[0] >= 6 and array.shape[1] > array.shape[0]:
        array = array.transpose()
    if array.shape[1] < 6:
        return []
    rows = array.tolist()
    return [[float(value) for value in row] for row in rows if isinstance(row, list)]


def _parse_detector_row(
    row: list[float],
    labels: list[str],
    threshold: float,
    image_size: tuple[int, int],
) -> dict[str, Any] | None:
    if len(row) < 6:
        return None
    width, height = image_size
    first_four = row[:4]
    score = row[4]
    class_index = int(round(row[5]))
    output_format = "xyxy_score_class"
    if len(row) > 6:
        if labels and len(row) == len(labels) + 5:
            objectness = row[4]
            class_scores = row[5:]
            class_index, class_score = max(enumerate(class_scores), key=lambda item: item[1])
            score = objectness * class_score
            output_format = "xywh_objectness_class_scores"
        else:
            class_scores = row[4:]
            class_index, score = max(enumerate(class_scores), key=lambda item: item[1])
            output_format = "xywh_class_scores"
    if score < threshold:
        return None
    region = _detector_region(first_four, width, height)
    if region is None:
        return None
    label = labels[class_index] if 0 <= class_index < len(labels) else str(class_index)
    return {
        "label": label,
        "score": round(float(score), 4),
        "class_index": class_index,
        "region": region,
        "output_format": output_format,
    }


def _detector_region(values: list[float], width: int, height: int) -> dict[str, float] | None:
    a, b, c, d = values
    scale_x = max(float(width), 1.0)
    scale_y = max(float(height), 1.0)
    if max(abs(a), abs(b), abs(c), abs(d)) <= 1.5:
        scale_x = 1.0
        scale_y = 1.0
    if c > a and d > b:
        x = a / scale_x
        y = b / scale_y
        w = (c - a) / scale_x
        h = (d - b) / scale_y
    else:
        x = (a - c / 2) / scale_x
        y = (b - d / 2) / scale_y
        w = c / scale_x
        h = d / scale_y
    x = max(0.0, min(1.0, x))
    y = max(0.0, min(1.0, y))
    w = max(0.0, min(1.0 - x, w))
    h = max(0.0, min(1.0 - y, h))
    if w <= 0.0 or h <= 0.0:
        return None
    return {"x": round(x, 6), "y": round(y, 6), "width": round(w, 6), "height": round(h, 6)}


def _crop_region(image: Image.Image, region: dict[str, float]) -> Image.Image:
    width, height = image.size
    left = int(max(0.0, region["x"]) * width)
    top = int(max(0.0, region["y"]) * height)
    right = int(min(1.0, region["x"] + region["width"]) * width)
    bottom = int(min(1.0, region["y"] + region["height"]) * height)
    if right <= left or bottom <= top:
        return image
    return image.crop((left, top, right, bottom))


def _embedding_vector(output: Any, np: Any) -> list[float]:
    array = np.asarray(output).astype("float32").reshape((-1,))
    values = [float(item) for item in array.tolist()]
    return _normalize_vector(values)


def _normalize_vector(values: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in values)) or 1.0
    return [round(value / norm, 6) for value in values]


def _speech_runtime_name() -> str | None:
    try:
        __import__("faster_whisper")
        return "faster-whisper"
    except Exception:
        try:
            __import__("whisper")
            return "whisper"
        except Exception:
            return None


def _speech_payload(
    media_kind: str,
    detected_mime: str | None,
    detections: list[dict[str, Any]],
    transcript: str | None,
    ocr_status: str,
    *,
    engine: str | None = None,
) -> dict[str, Any]:
    return {
        "media_kind": media_kind,
        "detected_mime": detected_mime,
        "ocr_status": ocr_status,
        "ocr_engine": engine,
        "ocr_text": transcript,
        "detector_maturity": "local_ml",
        "worker_version": "media-ml-adapters-1.0",
        "detections": detections,
    }


def _image_to_nchw(image: Image.Image, size: int, np: Any) -> Any:
    resized = image.convert("RGB").resize((size, size), Image.Resampling.BILINEAR)
    array = np.asarray(resized).astype("float32") / 255.0
    mean = np.array([0.485, 0.456, 0.406], dtype="float32")
    std = np.array([0.229, 0.224, 0.225], dtype="float32")
    normalized = (array - mean) / std
    return normalized.transpose(2, 0, 1)[None, :, :, :]


def _image_embedding_input(image: Image.Image, size: int, np: Any) -> Any:
    """Prepare image-embedding inputs using the configured model family."""
    if _image_embedding_preprocess_name() == "clip_openai":
        return _image_to_clip_nchw(image, size, np)
    return _image_to_nchw(image, size, np)


def _image_embedding_preprocess_name() -> str:
    value = os.environ.get(IMAGE_EMBEDDING_PREPROCESS_ENV, "clip_openai").strip().lower()
    return value if value in {"clip_openai", "imagenet"} else "clip_openai"


def _image_to_clip_nchw(image: Image.Image, size: int, np: Any) -> Any:
    """Match OpenCLIP's ViT preprocessing: bicubic shortest-edge resize and center crop."""
    rgb = image.convert("RGB")
    width, height = rgb.size
    shortest = max(min(width, height), 1)
    scale = size / shortest
    resized_width = max(size, round(width * scale))
    resized_height = max(size, round(height * scale))
    resized = rgb.resize((resized_width, resized_height), Image.Resampling.BICUBIC)
    left = max((resized_width - size) // 2, 0)
    top = max((resized_height - size) // 2, 0)
    cropped = resized.crop((left, top, left + size, top + size))
    array = np.asarray(cropped).astype("float32") / 255.0
    mean = np.array([0.48145466, 0.4578275, 0.40821073], dtype="float32")
    std = np.array([0.26862954, 0.26130258, 0.27577711], dtype="float32")
    normalized = (array - mean) / std
    return normalized.transpose(2, 0, 1)[None, :, :, :]


def _flatten_scores(output: Any, np: Any) -> list[float]:
    array = np.asarray(output).astype("float32")
    array = array.reshape((-1, array.shape[-1]))[0] if array.ndim >= 2 else array.reshape((-1,))
    values = [float(item) for item in array.tolist()]
    if not values:
        return []
    if min(values) < 0.0 or max(values) > 1.0:
        return _softmax(values)
    return values


def _softmax(values: list[float]) -> list[float]:
    highest = max(values)
    exps = [math.exp(value - highest) for value in values]
    total = sum(exps) or 1.0
    return [value / total for value in exps]


def _top_scores(scores: list[float], threshold: float, limit: int) -> list[tuple[int, float]]:
    ranked = sorted(enumerate(scores), key=lambda item: item[1], reverse=True)
    return [(index, score) for index, score in ranked[:limit] if score >= threshold]


def _read_labels(path: str) -> list[str]:
    try:
        return [
            line.strip()[:64]
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def _safe_label(label: str) -> str:
    safe = "_".join(label.lower().replace("/", " ").split())
    return "".join(char for char in safe if char.isalnum() or char == "_")[:64] or "unknown"


def _region(x: float, y: float, w: float, h: float, width: int, height: int) -> dict[str, float]:
    return {
        "x": round(x / max(width, 1), 6),
        "y": round(y / max(height, 1), 6),
        "width": round(w / max(width, 1), 6),
        "height": round(h / max(height, 1), 6),
    }


def _int_env(name: str, default: int) -> int:
    try:
        return max(32, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return max(0.0, min(1.0, float(os.environ.get(name, str(default)))))
    except ValueError:
        return default


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
