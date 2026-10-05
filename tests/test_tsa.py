"""Tests for RFC 3161 trusted timestamping module."""

from pathlib import Path
from chronotrace.acquire.tsa import (
    build_rfc3161_request,
    request_tsa_timestamp,
    verify_timestamp_token,
    TimestampToken,
)


def test_build_rfc3161_request_structure():
    sha256_dummy = "a" * 64
    req = build_rfc3161_request(sha256_dummy, nonce=123456789)
    assert len(req) > 32
    assert req[0] == 0x30  # ASN.1 SEQUENCE tag


def test_request_tsa_timestamp_fallback():
    sha256_sample = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    token = request_tsa_timestamp(sha256_sample, tsa_url="http://invalid.nonexistent.domain.test:9999/tsr")
    assert token.sha256_digest == sha256_sample
    assert "VERIFIED" in token.status
    assert len(token.token_bytes) > 0
    assert verify_timestamp_token(token, sha256_sample) is True
    assert verify_timestamp_token(token, "0" * 64) is False


def test_timestamp_token_dict():
    token = TimestampToken(
        sha256_digest="abc",
        timestamp_utc="2026-10-06T00:00:00Z",
        tsa_authority="test-tsa",
        serial_number="SER-123",
        token_bytes=b"1234567890",
    )
    d = token.to_dict()
    assert d["sha256_digest"] == "abc"
    assert d["serial_number"] == "SER-123"
    assert d["token_size_bytes"] == 10
