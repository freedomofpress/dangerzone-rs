//! Components and logic to handle OCR

use anyhow::Result;

use crate::PageData;

pub(crate) mod kreuzberg_tesseract;
pub(crate) mod pdf_renderer;
pub(crate) use self::kreuzberg_tesseract::KreuzbergTesseractOcr;

/// Object holding coordinates and size data of OCR object
#[derive(Clone, Copy, Debug)]
pub(crate) struct OcrVBox {
    /// X-coordinate
    pub x: i32,
    /// Y-coordinate
    pub y: i32,
    /// Width
    pub w: i32,
    /// Height
    pub h: i32,
}

/// Object for each word on a page
///
/// We use word-level granularity for OCR.
/// The fields in this struct are richer then storing only
/// the text and coordinates + sizing properties since that isn't
/// sufficient to do precise OCR.
#[derive(Debug)]
pub(crate) struct OcrWord {
    /// Text recognized by the OCR
    pub text: String,
    /// Coordinates + sizing properties
    pub vbox: OcrVBox,
}

/// Object for each page in a document
///
/// An `OcrPage` contains it's `OcrWord`'s. Together they
/// form the whole document.
pub(crate) struct OcrPage {
    /// OCR word-boxes present on this page
    words: Vec<OcrWord>,
}

impl OcrPage {
    fn new(words: Vec<OcrWord>) -> Self {
        Self { words }
    }

    pub(crate) fn words(&self) -> &[OcrWord] {
        &self.words
    }

    #[cfg(test)]
    pub(crate) fn from_test_words(words: Vec<(&str, i32, i32, i32, i32)>) -> Self {
        Self::new(
            words
                .into_iter()
                .map(|(text, x, y, w, h)| OcrWord {
                    text: text.to_string(),
                    vbox: OcrVBox { x, y, w, h },
                })
                .collect(),
        )
    }
}

/// Trait implemented by OCR backends
///
/// This trait provides a generic contract for doing OCR on a page which
/// the different OCR backends will follow. This way we keep our OCR
/// implementation modular.
pub(crate) trait OcrBackend {
    /// Run OCR for multiple pages.
    /// Each back-end can defer this method call to it's own internal implementation
    /// to handle OCR on different pages (e.g parallel vs sequential).
    fn ocr_pages(&self, pages: &[PageData]) -> Result<Vec<OcrPage>>;
}
