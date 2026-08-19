#!/usr/bin/env python3
"""Basic unit tests for AegisScan."""

import pytest
from scanner import WebSecurityScanner, VERSION


def test_version():
    assert VERSION == "3.2"


def test_scanner_init():
    scanner = WebSecurityScanner("https://example.com")
    assert scanner.target == "https://example.com"
    assert scanner.hostname == "example.com"
    assert scanner.results["target"] == "https://example.com"


def test_mask_secret():
    masked = WebSecurityScanner._mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA")
    assert "*" in masked
    assert masked.endswith("MPLE")


def test_add_finding():
    scanner = WebSecurityScanner("https://example.com")
    scanner.add_finding(
        finding_id="TEST-001",
        title="Test finding",
        severity="LOW",
        confidence="HIGH",
        score=1,
        evidence="test",
        remediation="none",
        category="Test",
    )
    assert len(scanner.results["findings"]) == 1
    assert scanner.results["findings"][0]["id"] == "TEST-001"
