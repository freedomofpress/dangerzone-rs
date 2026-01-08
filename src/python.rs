#![allow(clippy::useless_conversion)]

use crate::{
    apply_ocr_fn as core_apply_ocr_fn, convert_doc_to_pixels as core_convert_doc_to_pixels,
    convert_document as core_convert_document, parse_pixel_data as core_parse_pixel_data,
    pixels_to_pdf as core_pixels_to_pdf, PageData,
};
/// Python bindings for the dangerzone-rs library using PyO3
///
/// This module provides PyO3 wrappers around the core Rust functionality,
/// converting anyhow::Result to PyResult for Python compatibility.
use pyo3::prelude::*;

/// Wrapper for parse_pixel_data that converts Result to PyResult
#[pyfunction]
fn parse_pixel_data(data: Vec<u8>) -> PyResult<Vec<PageData>> {
    core_parse_pixel_data(data)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

/// Wrapper for convert_doc_to_pixels that converts Result to PyResult
#[pyfunction]
fn convert_doc_to_pixels(input_path: String) -> PyResult<Vec<u8>> {
    core_convert_doc_to_pixels(input_path)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Wrapper for pixels_to_pdf that converts Result to PyResult
#[pyfunction]
fn pixels_to_pdf(pages: Vec<PageData>, output_path: String) -> PyResult<()> {
    core_pixels_to_pdf(pages, output_path)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Wrapper for convert_document that converts Result to PyResult
#[pyfunction]
fn convert_document(input_path: String, output_path: String, apply_ocr: bool) -> PyResult<()> {
    core_convert_document(input_path, output_path, apply_ocr)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Wrapper for apply_ocr_fn that converts Result to PyResult
#[pyfunction]
fn apply_ocr_fn(input_pdf: String, output_pdf: String) -> PyResult<()> {
    core_apply_ocr_fn(input_pdf, output_pdf)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// PyO3 module definition
#[pymodule]
pub fn dangerzone_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PageData>()?;
    m.add_function(wrap_pyfunction!(parse_pixel_data, m)?)?;
    m.add_function(wrap_pyfunction!(convert_doc_to_pixels, m)?)?;
    m.add_function(wrap_pyfunction!(pixels_to_pdf, m)?)?;
    m.add_function(wrap_pyfunction!(convert_document, m)?)?;
    m.add_function(wrap_pyfunction!(apply_ocr_fn, m)?)?;
    Ok(())
}
