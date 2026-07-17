#![allow(clippy::useless_conversion)]

use crate::{
    apply_ocr_fn as core_apply_ocr_fn, convert_doc_to_pixels as core_convert_doc_to_pixels,
    convert_document as core_convert_document, parse_pixel_data as core_parse_pixel_data,
    pixels_to_pdf as core_pixels_to_pdf, PageData as CorePageData,
};
/// Python bindings for the dangerzone-rs library using PyO3
///
/// This module provides PyO3 wrappers around the core Rust functionality,
/// converting anyhow::Result to PyResult for Python compatibility.
use pyo3::prelude::*;

/// Python-compatible wrapper for PageData
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct PageData {
    #[pyo3(get)]
    pub width: u16,
    #[pyo3(get)]
    pub height: u16,
    #[pyo3(get)]
    pub pixels: Vec<u8>,
}

#[pymethods]
impl PageData {
    #[new]
    pub fn new(width: u16, height: u16, pixels: Vec<u8>) -> Self {
        PageData {
            width,
            height,
            pixels,
        }
    }
}

impl From<CorePageData> for PageData {
    fn from(core: CorePageData) -> Self {
        PageData {
            width: core.width,
            height: core.height,
            pixels: core.pixels,
        }
    }
}

impl From<PageData> for CorePageData {
    fn from(py: PageData) -> Self {
        CorePageData {
            width: py.width,
            height: py.height,
            pixels: py.pixels,
        }
    }
}

/// Wrapper for parse_pixel_data that converts Result to PyResult
#[pyfunction]
fn parse_pixel_data(data: Vec<u8>) -> PyResult<Vec<PageData>> {
    core_parse_pixel_data(data)
        .map(|pages| pages.into_iter().map(PageData::from).collect())
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
    let core_pages: Vec<CorePageData> = pages.into_iter().map(CorePageData::from).collect();
    core_pixels_to_pdf(core_pages, output_path)
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
fn apply_ocr_fn(input_path: String, output_path: String) -> PyResult<()> {
    core_apply_ocr_fn(input_path, output_path)
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
