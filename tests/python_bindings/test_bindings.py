"""Smoke tests for the dangerzone_rs Python bindings.

These tests exercise the PyO3 surface without requiring podman, network, or
ocrmypdf. They mirror a subset of the Rust unit tests in src/lib.rs to make
sure the PyO3 wrappers correctly bridge data across the FFI boundary.

Run via `make test-python` from the repository root.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest

import dangerzone_rs as dz


# ---------------------------------------------------------------------------
# Module-level surface
# ---------------------------------------------------------------------------


def test_module_exposes_expected_symbols():
    """Guard against accidental renames or removals on the Rust side."""
    expected = {
        "PageData",
        "parse_pixel_data",
        "pixels_to_pdf",
        "convert_document",
        "convert_doc_to_pixels",
        "apply_ocr_fn",
    }
    actual = set(dir(dz))
    missing = expected - actual
    assert not missing, f"dangerzone_rs is missing exports: {missing}"


# ---------------------------------------------------------------------------
# PageData
# ---------------------------------------------------------------------------


def test_page_data_constructor_and_getters():
    pixels = bytes([255, 0, 0] * 4)  # 2x2 red
    page = dz.PageData(2, 2, pixels)
    assert page.width == 2
    assert page.height == 2
    # PyO3 returns the bytes as a list[int] for Vec<u8>; both must match.
    assert bytes(page.pixels) == pixels


def test_page_data_rejects_negative_dimensions():
    # u16 in Rust; a negative number must not cross the boundary.
    with pytest.raises((OverflowError, TypeError)):
        dz.PageData(-1, 1, b"")


# ---------------------------------------------------------------------------
# parse_pixel_data: mirrors the Rust `test_pixel_data_parsing`
# ---------------------------------------------------------------------------


def _build_pixel_stream(pages: list[tuple[int, int, bytes]]) -> bytes:
    """Build the binary format the container produces: BE u16 page count,
    then per page (BE u16 width, BE u16 height, width*height*3 RGB bytes)."""
    out = bytearray()
    out += struct.pack(">H", len(pages))
    for w, h, px in pages:
        assert len(px) == w * h * 3
        out += struct.pack(">H", w)
        out += struct.pack(">H", h)
        out += px
    return bytes(out)


def test_parse_pixel_data_single_page():
    width, height = 100, 50
    pixels = bytes([128] * (width * height * 3))
    stream = _build_pixel_stream([(width, height, pixels)])

    pages = dz.parse_pixel_data(stream)

    assert len(pages) == 1
    assert pages[0].width == width
    assert pages[0].height == height
    assert len(pages[0].pixels) == width * height * 3


def test_parse_pixel_data_multi_page():
    pages_in = [
        (10, 10, bytes([1] * 10 * 10 * 3)),
        (20, 5, bytes([2] * 20 * 5 * 3)),
        (1, 1, bytes([3, 4, 5])),
    ]
    stream = _build_pixel_stream(pages_in)

    pages = dz.parse_pixel_data(stream)

    assert len(pages) == 3
    for got, (w, h, px) in zip(pages, pages_in):
        assert got.width == w
        assert got.height == h
        assert bytes(got.pixels) == px


def test_parse_pixel_data_rejects_truncated_stream():
    # Promise 1 page, give no page header.
    bad = struct.pack(">H", 1)
    with pytest.raises(Exception):
        dz.parse_pixel_data(bad)


def test_parse_pixel_data_rejects_short_pixel_buffer():
    # Promise 1 page of 2x2 (12 bytes) but only supply 6.
    bad = struct.pack(">HHH", 1, 2, 2) + bytes([0] * 6)
    with pytest.raises(Exception):
        dz.parse_pixel_data(bad)


# ---------------------------------------------------------------------------
# pixels_to_pdf: mirrors the Rust `test_pdf_generation`
# ---------------------------------------------------------------------------


def test_pixels_to_pdf_writes_valid_pdf(tmp_path: Path):
    width, height = 10, 10
    pixels = bytes([255, 0, 0] * (width * height))  # solid red
    page = dz.PageData(width, height, pixels)

    output = tmp_path / "out.pdf"
    dz.pixels_to_pdf([page], str(output))

    assert output.exists(), "pixels_to_pdf should have written the file"
    data = output.read_bytes()
    assert data.startswith(b"%PDF-1.4"), "PDF header missing"
    assert b"%%EOF" in data, "PDF trailer missing"
    assert b"/Type /Catalog" in data
    assert b"/Type /Pages" in data
    assert b"/Type /Page" in data
    assert b"/Type /XObject" in data
    assert b"/Filter /FlateDecode" in data, "expected Flate-compressed stream"


def test_pixels_to_pdf_rejects_empty_page_list(tmp_path: Path):
    output = tmp_path / "should-not-exist.pdf"
    with pytest.raises(Exception):
        dz.pixels_to_pdf([], str(output))


def test_pixels_to_pdf_round_trip_through_parse_pixel_data(tmp_path: Path):
    """Build a stream, parse it via the bindings, then render to PDF."""
    pages_in = [(8, 4, bytes([0xAB] * 8 * 4 * 3))]
    stream = _build_pixel_stream(pages_in)
    pages = dz.parse_pixel_data(stream)

    output = tmp_path / "round-trip.pdf"
    dz.pixels_to_pdf(pages, str(output))

    data = output.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    assert b"%%EOF" in data


# ---------------------------------------------------------------------------
# convert_doc_to_pixels / convert_document / apply_ocr_fn
#
# These require podman + the signed container image (and ocrmypdf or PDFKit
# for OCR) so they are not exercised here. They are covered by the manual
# `demo/demo.py` and by Rust-side integration tests when present.
# ---------------------------------------------------------------------------


def test_convert_document_is_callable():
    """Cheap check: the symbol must be a callable, even if we don't run it."""
    assert callable(dz.convert_document)


def test_convert_doc_to_pixels_is_callable():
    assert callable(dz.convert_doc_to_pixels)


def test_apply_ocr_fn_is_callable():
    assert callable(dz.apply_ocr_fn)
