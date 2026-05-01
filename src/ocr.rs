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
