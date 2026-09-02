"""Tests for media analysis sensitive pattern and crypto seed recognition."""

from forensix_forensic.media_analysis_worker import (
    detect_sensitive_patterns,
    luhn_validate,
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
