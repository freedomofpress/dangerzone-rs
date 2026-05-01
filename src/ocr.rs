//! Components and logic to handle OCR

/// Object for each word in the document
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

/// Trait implemented by OCR backends
///
/// This trait provides a generic contract for doing OCR on a page which
/// the different OCR backends will follow. This way we keep our OCR
/// implementation modular.
trait OcrBackend {
    /// Detect words on a single page
    ///
    /// `pixels` must contain `width * height * 3` bytes in RGB order.
    fn ocr_page(&self, pixels: &[u8], width: u16, height: u16) -> Vec<OcrWord>;
}

