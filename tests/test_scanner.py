"""Basic unit tests for AegisScan."""

import pytest
from scanner import WebSecurityScanner, VERSION, SCANNER_NAME


def test_version():
    assert VERSION == "3.2"


def test_scanner_name():
    assert SCANNER_NAME == "AegisScan"


def test_scanner_init():
    scanner = WebSecurityScanner("https://example.com")
    assert scanner.target == "https://example.com"
    assert scanner.results["scanner"]["name"] == "AegisScan"
    assert scanner.results["risk_score"] == 0
    assert scanner.results["risk_level"] == "LOW"


def test_mask_secret_short():
    assert WebSecurityScanner._mask_secret("abc") == "***"


def test_mask_secret_long():
    masked = WebSecurityScanner._mask_secret("ABCDEFGHIJKLMNOP")
    assert masked.startswith("ABCD")
    assert masked.endswith("MNOP")
    assert "*" in masked
