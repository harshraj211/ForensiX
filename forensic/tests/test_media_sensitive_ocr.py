"""Tests for media analysis sensitive pattern and crypto seed recognition."""

import sys
import types

from PIL import Image

from forensix_forensic import media_ml_adapters
from forensix_forensic.media_analysis_worker import (
    classify,
    detect_sensitive_patterns,
    luhn_validate,
)
from forensix_forensic.media_ml_adapters import (
    image_model_detections,
    speech_adapter_status,
    transcribe_media,
)


def test_luhn_validate():
    # Valid Visa test number
    assert luhn_validate("4532015112830366") is True
    # Invalid card number
    assert luhn_validate("4532015112830367") is False
    # Short string
    assert luhn_validate("12345") is False


def test_detect_sensitive_patterns_crypto_seed():
    # 12-word BIP-39 mnemonic phrase
    mnemonic = (
        "abandon ability able about above absent absorb abstract absurd abuse access accident"
    )
    findings = detect_sensitive_patterns(mnemonic)
    assert len(findings) == 1
    assert findings[0]["type"] == "crypto_seed_phrase"
    assert findings[0]["word_count"] == 12
    assert findings[0]["confidence"] >= 0.90


def test_detect_sensitive_patterns_payment_card():
    text = "Payment details: Card 4532-0151-1283-0366 Exp 12/28 CVV 123"
    findings = detect_sensitive_patterns(text)
    assert len(findings) >= 1
    card_findings = [f for f in findings if f["type"] == "payment_card"]
    assert len(card_findings) == 1
    assert "4532 **** **** 0366" in card_findings[0]["summary"]


def test_detect_sensitive_patterns_private_key():
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n"
        "-----END PRIVATE KEY-----"
    )
    findings = detect_sensitive_patterns(pem)
    assert len(findings) >= 1
    assert any(f["type"] == "cryptographic_private_key" for f in findings)


def test_detect_sensitive_patterns_empty():
    assert detect_sensitive_patterns(None) == []
    assert detect_sensitive_patterns("Just a normal photo of a cat in the park") == []


def test_image_classifier_emits_local_ml_adapter_status(monkeypatch):
    monkeypatch.delenv("FORENSIX_OBJECT_ONNX_MODEL", raising=False)
    image = Image.new("RGB", (64, 64), color="white")
    labels = classify(image, {"gps_present": False})
    label_names = {item["label"] for item in labels}
    assert "object_detection_model_not_configured" in label_names
    assert any(label.startswith("face_") for label in label_names)


def test_speech_adapter_reports_model_configuration_state(monkeypatch, tmp_path):
    monkeypatch.delenv("FORENSIX_WHISPER_MODEL", raising=False)
    assert speech_adapter_status()["label"] == "speech_transcription_model_not_configured"

    missing = tmp_path / "missing.bin"
    monkeypatch.setenv("FORENSIX_WHISPER_MODEL", str(missing))
    status = speech_adapter_status()
    assert status["label"] == "speech_transcription_model_missing"
    assert status["status"] == "unavailable"


def test_onnx_object_adapter_runs_configured_classifier(monkeypatch, tmp_path):
    class _Array:
        ndim = 2
        shape = (1, 3)

        def astype(self, _dtype):
            return self

        def reshape(self, _shape):
            return self

        def __getitem__(self, _index):
            return self

        def tolist(self):
            return [0.05, 0.90, 0.05]

    class _Input:
        name = "input"

    class _Session:
        def __init__(self, model_path, providers):
            self.model_path = model_path
            self.providers = providers

        def get_inputs(self):
            return [_Input()]

        def run(self, _outputs, _inputs):
            return [_Array()]

    fake_numpy = types.SimpleNamespace(asarray=lambda _value: _Array())
    fake_ort = types.SimpleNamespace(InferenceSession=_Session)
    monkeypatch.setitem(sys.modules, "numpy", fake_numpy)
    monkeypatch.setitem(sys.modules, "onnxruntime", fake_ort)
    monkeypatch.setattr(media_ml_adapters, "_image_to_nchw", lambda *_args: object())
    model = tmp_path / "model.onnx"
    model.write_bytes(b"fake")
    labels = tmp_path / "labels.txt"
    labels.write_text("cat\ndog\ncar\n", encoding="utf-8")
    monkeypatch.setenv("FORENSIX_OBJECT_ONNX_MODEL", str(model))
    monkeypatch.setenv("FORENSIX_OBJECT_LABELS", str(labels))
    monkeypatch.setenv("FORENSIX_OBJECT_SCORE_THRESHOLD", "0.2")

    detections = image_model_detections(Image.new("RGB", (32, 32), color="white"))

    assert any(item["label"] == "object_dog" for item in detections)
    assert any(item.get("status") == "completed" for item in detections)


def test_onnx_object_adapter_emits_yolo_regions(monkeypatch, tmp_path):
    class _Array:
        def __init__(self, data):
            self.data = data
            self.ndim = _ndim(data)
            self.shape = _shape(data)

        def astype(self, _dtype):
            return self

        def reshape(self, shape):
            if shape == (-1, self.shape[-1]):
                return _Array(_flatten_rows(self.data, self.shape[-1]))
            return self

        def transpose(self):
            return _Array([list(row) for row in zip(*self.data, strict=True)])

        def __getitem__(self, index):
            return _Array(self.data[index])

        def tolist(self):
            return self.data

    def _ndim(value):
        depth = 0
        while isinstance(value, list):
            depth += 1
            value = value[0] if value else None
        return depth

    def _shape(value):
        shape = []
        while isinstance(value, list):
            shape.append(len(value))
            value = value[0] if value else None
        return tuple(shape)

    def _flatten_rows(value, width):
        if not isinstance(value, list):
            return []
        if value and all(not isinstance(item, list) for item in value):
            return [value] if len(value) == width else []
        rows = []
        for item in value:
            rows.extend(_flatten_rows(item, width))
        return rows

    class _Input:
        name = "input"

    class _Session:
        def __init__(self, model_path, providers):
            self.model_path = model_path
            self.providers = providers

        def get_inputs(self):
            return [_Input()]

        def run(self, _outputs, _inputs):
            return [[[10.0, 20.0, 40.0, 60.0, 0.91, 1.0]]]

    fake_numpy = types.SimpleNamespace(asarray=lambda value: _Array(value))
    fake_ort = types.SimpleNamespace(InferenceSession=_Session)
    monkeypatch.setitem(sys.modules, "numpy", fake_numpy)
    monkeypatch.setitem(sys.modules, "onnxruntime", fake_ort)
    monkeypatch.setattr(media_ml_adapters, "_image_to_nchw", lambda *_args: object())
    model = tmp_path / "detector.onnx"
    model.write_bytes(b"fake")
    labels = tmp_path / "labels.txt"
    labels.write_text("person\ncar\n", encoding="utf-8")
    monkeypatch.setenv("FORENSIX_OBJECT_ONNX_MODEL", str(model))
    monkeypatch.setenv("FORENSIX_OBJECT_LABELS", str(labels))
    monkeypatch.setenv("FORENSIX_OBJECT_SCORE_THRESHOLD", "0.2")

    detections = image_model_detections(Image.new("RGB", (100, 100), color="white"))

    car = next(item for item in detections if item["label"] == "object_car")
    assert car["region"] == {"x": 0.1, "y": 0.2, "width": 0.3, "height": 0.4}
    assert car["details"]["output_format"] == "xyxy_score_class"


def test_face_embedding_adapter_returns_normalized_vector(monkeypatch, tmp_path):
    class _Array:
        def __init__(self, data):
            self.data = data

        def astype(self, _dtype):
            return self

        def reshape(self, _shape):
            return self

        def tolist(self):
            return self.data

    fake_numpy = types.SimpleNamespace(asarray=lambda value: _Array(value))
    monkeypatch.setitem(sys.modules, "numpy", fake_numpy)
    monkeypatch.setitem(sys.modules, "onnxruntime", types.SimpleNamespace())
    monkeypatch.setattr(media_ml_adapters, "_image_to_nchw", lambda *_args: object())
    monkeypatch.setattr(media_ml_adapters, "_run_onnx_outputs", lambda *_args: [[3.0, 4.0]])
    model = tmp_path / "face.onnx"
    model.write_bytes(b"fake")
    monkeypatch.setenv("FORENSIX_FACE_EMBEDDING_ONNX_MODEL", str(model))

    payload = media_ml_adapters._face_embedding_for_region(
        Image.new("RGB", (100, 100), color="white"),
        {"x": 0.1, "y": 0.1, "width": 0.5, "height": 0.5},
    )

    assert payload is not None
    assert payload["embedding_status"] == "completed"
    assert payload["embedding"] == [0.6, 0.8]


def test_image_embedding_adapter_emits_clip_style_detection(monkeypatch, tmp_path):
    class _Array:
        def __init__(self, data):
            self.data = data

        def astype(self, _dtype):
            return self

        def reshape(self, _shape):
            return self

        def tolist(self):
            return self.data

    fake_numpy = types.SimpleNamespace(asarray=lambda value: _Array(value))
    monkeypatch.setitem(sys.modules, "numpy", fake_numpy)
    monkeypatch.setitem(sys.modules, "onnxruntime", types.SimpleNamespace())
    monkeypatch.setattr(media_ml_adapters, "_image_embedding_input", lambda *_args: object())
    monkeypatch.setattr(media_ml_adapters, "_run_onnx_outputs", lambda *_args: [[3.0, 4.0]])
    model = tmp_path / "clip.onnx"
    model.write_bytes(b"fake")
    monkeypatch.setenv("FORENSIX_IMAGE_EMBEDDING_ONNX_MODEL", str(model))

    detection = media_ml_adapters._image_embedding_onnx(Image.new("RGB", (100, 100), color="white"))

    assert detection is not None
    assert detection["label"] == "image_embedding"
    assert detection["details"]["embedding"] == [0.6, 0.8]
    assert detection["details"]["embedding_family"] == "clip_style_onnx"
    assert detection["details"]["preprocessing"] == "clip_openai"


def test_clip_image_embedding_preprocessing_matches_exported_model_metadata():
    import numpy as np

    tensor = media_ml_adapters._image_to_clip_nchw(
        Image.new("RGB", (100, 200), color=(255, 0, 0)), 224, np
    )

    assert tensor.shape == (1, 3, 224, 224)
    np.testing.assert_allclose(
        tensor[0, :, 0, 0],
        np.array(
            [
                (1.0 - 0.48145466) / 0.26862954,
                (0.0 - 0.4578275) / 0.26130258,
                (0.0 - 0.40821073) / 0.27577711,
            ],
            dtype="float32",
        ),
        rtol=1e-5,
        atol=1e-5,
    )


def test_transcribe_media_uses_configured_whisper_runtime(monkeypatch, tmp_path):
    class _Model:
        def transcribe(self, source):
            return {
                "text": "hello forensic audio",
                "language": "en",
                "segments": [{"start": 0.0, "end": 1.25, "text": "hello forensic audio"}],
            }

    fake_whisper = types.SimpleNamespace(load_model=lambda _model: _Model())
    monkeypatch.setitem(sys.modules, "whisper", fake_whisper)
    monkeypatch.setitem(sys.modules, "faster_whisper", None)
    model = tmp_path / "tiny.pt"
    model.write_bytes(b"fake")
    audio = tmp_path / "sample.wav"
    audio.write_bytes(b"fake")
    monkeypatch.setenv("FORENSIX_WHISPER_MODEL", str(model))

    payload = transcribe_media(audio, "audio", "audio/wav")

    assert payload["ocr_status"] == "completed"
    assert payload["ocr_engine"] == "whisper"
    assert payload["ocr_text"] == "hello forensic audio"
    assert payload["detections"][0]["details"]["segments"][0]["end"] == 1.25
