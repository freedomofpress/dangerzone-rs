//! Components and logic to handle OCR

use std::path::PathBuf;

use crate::PageData;
use kreuzberg_tesseract::{Pix, TessPageIteratorLevel, TesseractAPI};

/// DPI used by container
pub const DEFAULT_DPI: i32 = 150;

/// Object for each word on a page
///
/// We use word-level granularity for OCR. The text-content of a
/// word is wrapped in this object together with the positioning
/// and sizing properties.
#[derive(Debug)]
struct OcrWord {
    /// Text-content of the word
    text: String,
    /// x-axis positioning
    x: i32,
    /// y-axis positioning
    y: i32,
    /// Width of the word-box
    w: i32,
    /// Height of the word-box
    h: i32,
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
}

/// Trait implemented by OCR backends
///
/// This trait provides a generic contract for doing OCR on a page which
/// the different OCR backends will follow. This way we keep our OCR
/// implementation modular.
trait OcrBackend {
    /// Detect words on a single page
    ///
    /// `pixels` must contain `width * height * 3` bytes in RGB order.
    fn ocr_page(&self, pixels: &[u8], width: u16, height: u16) -> OcrPage;
}

/// Run OCR for multiple pages with specified OCR-backend
fn ocr_pages<B: OcrBackend>(pages: &[PageData], backend: &B) -> Vec<OcrPage> {
    pages
        .iter()
        .map(|page| backend.ocr_page(&page.pixels, page.width, page.height))
        .collect()
}

/// OCR backend powered by the `kreuzberg-tesseract` used for Linux
struct KreuzbergTesseractOcr;

impl KreuzbergTesseractOcr {
    /// Resolve the tessdata directory used to initialize Tesseract
    ///
    /// `TESSDATA_PREFIX` has priority when set. Otherwise we use the tessdata
    /// bundled by `kreuzberg-tesseract`.
    fn tessdata_dir() -> Option<PathBuf> {
        if let Ok(path) = std::env::var("TESSDATA_PREFIX") {
            return Some(PathBuf::from(path));
        }

        option_env!("TESSDATA_PREFIX_BUNDLED").map(PathBuf::from)
    }
}

impl OcrBackend for KreuzbergTesseractOcr {
    fn ocr_page(&self, pixels: &[u8], width: u16, height: u16) -> OcrPage {
        // Pass container's bytes directly using Leptonica's Pix wrapper exposed
        // by `kreuzberg-tesseract`.
        let mut pix = match Pix::from_raw_rgb(pixels, width.into(), height.into()) {
            Ok(pix) => pix,
            Err(_) => return OcrPage::new(Vec::new()),
        };

        // The container renders pages at 150 DPI. Store that resolution on the
        // Pix as image metadata so Tesseract can interpret text size correctly.
        let _ = pix.set_resolution(DEFAULT_DPI, DEFAULT_DPI);

        // Initialize tesseract engine for this page to do OCR.
        // TODO: Find a way to re-use same instance for all pages.
        let api = match TesseractAPI::new() {
            Ok(api) => api,
            Err(_) => return OcrPage::new(Vec::new()),
        };

        // Seed tesseract with trained language data.
        // TODO: Currently we only support English. Support other languages to.
        // TODO: Check if we can seed the trained data for the whole PDF instead of per-page.
        let tessdata_dir = match Self::tessdata_dir() {
            Some(path) => path,
            None => return OcrPage::new(Vec::new()),
        };
        if api.init(&tessdata_dir, "eng").is_err() {
            return OcrPage::new(Vec::new());
        }

        // Give Tesseract the Leptonica image. `set_image_2` borrows the Pix
        // pointer; keep `pix` alive for the rest of this method.
        if api.set_image_2(pix.as_ptr()).is_err() {
            return OcrPage::new(Vec::new());
        }

        // Also set the source resolution on the Tesseract API. Some OCR paths
        // read DPI from the engine state rather than from the Pix metadata.
        let _ = api.set_source_resolution(DEFAULT_DPI);

        // Ask Tesseract for word-level text components. The returned boxes are
        // image-coordinate rectangles: x, y, width, height.
        let boxes = match api.get_component_images(TessPageIteratorLevel::RIL_WORD, true) {
            Ok(boxes) => boxes,
            Err(_) => return OcrPage::new(Vec::new()),
        };

        // Put recognized words in a `OcrWord` object and return in vector.
        let mut words = Vec::new();
        for &(x, y, w, h) in boxes.iter() {
            // Limit recognition to the current word box.
            let _ = api.set_rectangle(x, y, w, h);

            // Ask tesseract for text in word box.
            if let Ok(text) = api.get_utf8_text() {
                let text = text.trim().to_string(); // Remove obsoletely returned newlines and whitespaces.
                if !text.is_empty() {
                    words.push(OcrWord { text, x, y, w, h });
                }
            }
        }

        OcrPage::new(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeOcrBackend;

    impl OcrBackend for FakeOcrBackend {
        fn ocr_page(&self, _pixels: &[u8], width: u16, height: u16) -> OcrPage {
            OcrPage::new(vec![OcrWord {
                text: format!("{width}x{height}"),
                x: 1,
                y: 2,
                w: 3,
                h: 4,
            }])
        }
    }

    #[test]
    fn ocr_pages_runs_backend_for_each_page() {
        let pages = vec![
            PageData::new(10, 20, vec![255; 10 * 20 * 3]),
            PageData::new(30, 40, vec![255; 30 * 40 * 3]),
        ];

        let result = ocr_pages(&pages, &FakeOcrBackend);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].words[0].text, "10x20");
        assert_eq!(result[1].words[0].text, "30x40");
    }
}
