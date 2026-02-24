"""
Tests for scribe.analysis
=========================
Run with:  pytest tests/test_analysis.py -v
"""

from __future__ import annotations

import pytest

from scribe.analysis import (
    AnalysisConfig,
    ExtractionResult,
    Mode,
    analyse,
    extract_strings_from_bytes,
    repair_wide_text,
)


# ---------------------------------------------------------------------------
# repair_wide_text
# ---------------------------------------------------------------------------

class TestRepairWideText:
    def test_removes_null_padding(self):
        # Simulate UTF-16-LE decoded as ASCII: 'H\x00e\x00l\x00l\x00o\x00'
        raw = "H\x00e\x00l\x00l\x00o\x00"
        assert repair_wide_text(raw) == "Hello"

    def test_removes_space_padding(self):
        raw = "H e l l o "
        assert repair_wide_text(raw) == "Hello"

    def test_passes_through_clean_text(self):
        assert repair_wide_text("Hello World") == "Hello World"

    def test_strips_non_printable(self):
        assert repair_wide_text("ab\x01\x1fcd") == "abcd"


# ---------------------------------------------------------------------------
# extract_strings_from_bytes
# ---------------------------------------------------------------------------

class TestExtractStringsFromBytes:
    def test_finds_ascii_string(self):
        data = b"\x00\x00Hello World\x00\x00"
        result = extract_strings_from_bytes(data)
        assert "Hello World" in result

    def test_finds_wide_string(self):
        wide = "Test".encode("utf-16-le")
        data = b"\x00" * 4 + wide + b"\x00" * 4
        result = extract_strings_from_bytes(data)
        assert "Test" in result

    def test_empty_bytes(self):
        assert extract_strings_from_bytes(b"") == ""


# ---------------------------------------------------------------------------
# analyse — Mode.NORMAL
# ---------------------------------------------------------------------------

class TestModeNormal:
    def test_extracts_printable_strings(self):
        source = "Some readable text\n\x01\x02\x03more text here"
        cfg    = AnalysisConfig(mode=Mode.NORMAL)
        results = analyse(source, cfg)
        values = [r.value for r in results]
        assert any("readable text" in v for v in values)

    def test_min_length_respected(self):
        source = "abc abcdef"
        cfg    = AnalysisConfig(mode=Mode.NORMAL, min_length=4)
        results = analyse(source, cfg)
        assert not any(len(r.value) < 4 for r in results)


# ---------------------------------------------------------------------------
# analyse — Mode.URL
# ---------------------------------------------------------------------------

class TestModeURL:
    def test_extracts_https_url(self):
        source = "garbage https://example.com/api?key=123 garbage"
        cfg    = AnalysisConfig(mode=Mode.URL)
        results = analyse(source, cfg)
        assert any("https://example.com" in r.value for r in results)

    def test_ignores_non_urls(self):
        source = "hello world foo bar baz"
        cfg    = AnalysisConfig(mode=Mode.URL)
        results = analyse(source, cfg)
        assert results == []

    def test_strips_trailing_punctuation(self):
        source = "see https://example.com/path."
        cfg    = AnalysisConfig(mode=Mode.URL)
        results = analyse(source, cfg)
        assert all(not r.value.endswith(".") for r in results)

    def test_multiple_urls(self):
        source = "http://foo.com and https://bar.org/page"
        cfg    = AnalysisConfig(mode=Mode.URL)
        results = analyse(source, cfg)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# analyse — Mode.PATHS
# ---------------------------------------------------------------------------

class TestModePaths:
    def test_windows_path(self):
        source = r"C:\Users\user\Documents\file.txt garbage data"
        cfg    = AnalysisConfig(mode=Mode.PATHS)
        results = analyse(source, cfg)
        assert any(r"C:\Users" in r.value for r in results)

    def test_unix_path(self):
        source = "config at /etc/app/config.yaml in production"
        cfg    = AnalysisConfig(mode=Mode.PATHS)
        results = analyse(source, cfg)
        assert any("/etc/app/config.yaml" in r.value for r in results)

    def test_no_false_positives(self):
        source = "hello world version 1.0"
        cfg    = AnalysisConfig(mode=Mode.PATHS)
        results = analyse(source, cfg)
        assert results == []


# ---------------------------------------------------------------------------
# analyse — Mode.GAME
# ---------------------------------------------------------------------------

class TestModeGame:
    def test_extracts_hex_offset(self):
        source = "LocalPlayer 0x12A4B0\nRandom garbage line"
        cfg    = AnalysisConfig(mode=Mode.GAME)
        results = analyse(source, cfg)
        assert any("LocalPlayer" in r.value for r in results)

    def test_extracts_keyword_line(self):
        source = "float Health = 100.0f;"
        cfg    = AnalysisConfig(mode=Mode.GAME)
        results = analyse(source, cfg)
        assert any("Health" in r.value for r in results)

    def test_skips_short_lines(self):
        source = "0x1"
        cfg    = AnalysisConfig(mode=Mode.GAME)
        results = analyse(source, cfg)
        # Too short — should be filtered
        assert not any(r.value == "0x1" for r in results)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_deduplication_on(self):
        source = "Hello World\nHello World\nHello World"
        cfg    = AnalysisConfig(mode=Mode.NORMAL, deduplicate=True)
        results = analyse(source, cfg)
        values = [r.value for r in results if "Hello World" in r.value]
        assert len(values) == 1

    def test_deduplication_off(self):
        source = "Hello World\nHello World"
        cfg    = AnalysisConfig(mode=Mode.NORMAL, deduplicate=False)
        results = analyse(source, cfg)
        values = [r.value for r in results if "Hello World" in r.value]
        assert len(values) >= 2


# ---------------------------------------------------------------------------
# ExtractionResult formatting
# ---------------------------------------------------------------------------

class TestExtractionResult:
    def test_plain_str(self):
        r = ExtractionResult(value="hello")
        assert str(r) == "hello"

    def test_with_meta(self):
        r = ExtractionResult(value="hello", meta="ID:0x001A")
        assert "ID:0x001A" in str(r)
        assert "hello" in str(r)

    def test_with_offset(self):
        r = ExtractionResult(value="hello", offset=0x1A0)
        assert "0x000001A0" in str(r)
