// TODO: A library shouldn't use anyhow::Result. Use e.g thiserror instead.
use anyhow::{Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use ocr::OcrBackend;
use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::process::{Command, Stdio};

use crate::ocr::KreuzbergTesseractOcr;

mod error;
mod ocr;
mod util;

pub use error::{CorruptedPageField, PageError, PixelDataError};
pub use util::{replace_control_chars, Untrusted};

pub const IMAGE_NAME: &str = "ghcr.io/freedomofpress/dangerzone/v1";
pub const DPI: usize = 150;
const MAX_SANITIZED_CHUNK_BYTES: u64 = 64 * 1024;
/// Maximum number of pages we accept from the sandbox.
pub const MAX_PAGES: u16 = 10000;
/// Maximum page width in pixels.
pub const MAX_PAGE_WIDTH: u16 = 10000;
/// Maximum page height in pixels.
pub const MAX_PAGE_HEIGHT: u16 = 10000;
/// How many bytes are needed to encode a single RGB pixel.
const BYTES_PER_PIXEL: usize = 3;

fn get_security_args() -> Vec<String> {
    vec![
        "--log-driver".to_string(),
        "none".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--cap-drop".to_string(),
        "all".to_string(),
        "--cap-add".to_string(),
        "SYS_CHROOT".to_string(),
        "--security-opt".to_string(),
        "label=type:container_engine_t".to_string(),
        "--network=none".to_string(),
        "-u".to_string(),
        "dangerzone".to_string(),
    ]
}

/// Check page dimensions and return the number of bytes the page takes.
fn expected_page_len(width: u16, height: u16) -> Result<usize, PageError> {
    if width == 0 || height == 0 || width > MAX_PAGE_WIDTH || height > MAX_PAGE_HEIGHT {
        return Err(PageError::InvalidDimensions { width, height });
    }
    Ok(width as usize * height as usize * BYTES_PER_PIXEL)
}

/// A single page of RGB pixels.
///
/// The fields are private so that a `PageData` always holds exactly
/// `width * height * 3` bytes, with dimensions within [`MAX_PAGE_WIDTH`] and
/// [`MAX_PAGE_HEIGHT`]. The PDF writer and the OCR backend rely on this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageData {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
}

impl PageData {
    /// Create a page from RGB pixels, row by row, 3 bytes per pixel.
    ///
    /// # Errors
    ///
    /// Returns an error if `width` or `height` is 0 or above the maximum, or if
    /// `pixels` is not exactly `width * height * 3` bytes long.
    pub fn new(width: u16, height: u16, pixels: Vec<u8>) -> Result<Self, PageError> {
        let expected = expected_page_len(width, height)?;
        if pixels.len() != expected {
            return Err(PageError::PixelLength {
                width,
                height,
                expected,
                actual: pixels.len(),
            });
        }
        Ok(PageData {
            width,
            height,
            pixels,
        })
    }

    /// Width in pixels.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// RGB pixels, row by row, 3 bytes per pixel.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Take the pixels out of the page, without copying them.
    pub fn into_pixels(self) -> Vec<u8> {
        self.pixels
    }
}

/// Reads big-endian integers and byte slices from the sandbox output,
/// without ever reading past its end.
struct PixelStreamReader<'a> {
    data: &'a [u8],
}

impl<'a> PixelStreamReader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.data.split_at_checked(n)?;
        // Overwrite the previous slice with the new one, advanced by the bytes
        // we've read.
        self.data = tail;
        Some(head)
    }

    fn read_u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
}

/// Parse the pixel stream that the sandbox writes to its stdout.
///
/// The stream is a big-endian `u16` page count, followed by each page's
/// `u16` width, `u16` height and `width * height * 3` bytes of RGB pixels.
/// It comes from the sandbox, so it is treated as untrusted: page counts and
/// dimensions are checked against [`MAX_PAGES`], [`MAX_PAGE_WIDTH`] and
/// [`MAX_PAGE_HEIGHT`], and truncated or trailing data is rejected.
///
/// # Errors
///
/// Returns an error if the stream does not follow this format, or if it goes
/// over one of the limits.
pub fn parse_pixel_data(data: &[u8]) -> Result<Vec<PageData>, PixelDataError> {
    let mut reader = PixelStreamReader { data };

    let page_count = reader.read_u16().ok_or(PixelDataError::MissingPageCount)?;
    if page_count == 0 {
        return Err(PixelDataError::NoPages);
    }
    if page_count > MAX_PAGES {
        return Err(PixelDataError::TooManyPages(page_count));
    }

    eprintln!("Document has {page_count} page(s)");

    let mut pages = Vec::with_capacity(page_count.into());

    for page in 1..=page_count {
        let width = reader.read_u16().ok_or(PixelDataError::Truncated {
            page,
            field: CorruptedPageField::Width,
        })?;
        let height = reader.read_u16().ok_or(PixelDataError::Truncated {
            page,
            field: CorruptedPageField::Height,
        })?;
        let num_bytes = expected_page_len(width, height)
            .map_err(|source| PixelDataError::InvalidPage { page, source })?;

        eprintln!("Page {page}: {width}x{height} pixels");

        let pixels = reader.take(num_bytes).ok_or(PixelDataError::Truncated {
            page,
            field: CorruptedPageField::Pixels,
        })?;

        pages.push(PageData {
            width,
            height,
            pixels: pixels.to_vec(),
        });
    }

    if !reader.data.is_empty() {
        return Err(PixelDataError::TrailingData(reader.data.len()));
    }

    Ok(pages)
}

/// Read from a source (mostly locked stderr/stdout) and write sanitized
/// text to given output. Output is marked as untrusted
fn forward_sanitized_text<R: BufRead, W: Write + IsTerminal>(
    mut reader: R,
    mut out: W,
) -> Result<()> {
    const ANSI_GRAY: &str = "\x1b[90m";
    const ANSI_RESET: &str = "\x1b[0m";
    const UNTRUSTED_PREFIX: &str = "UNTRUSTED> ";

    let mut line_buf = Vec::new();
    loop {
        line_buf.clear();
        let n = reader
            .by_ref()
            .take(MAX_SANITIZED_CHUNK_BYTES)
            .read_until(b'\n', &mut line_buf)
            .context("Failed to read output for sanitizing")?;
        if n == 0 {
            break;
        }

        let line = Untrusted::new(String::from_utf8_lossy(&line_buf).into_owned());
        let mut sanitized = line.sanitized(true);
        if !sanitized.ends_with('\n') {
            sanitized.push('\n');
        }
        let sanitized_untrusted_prefix = if out.is_terminal() {
            format!("{ANSI_GRAY}{UNTRUSTED_PREFIX}{sanitized}{ANSI_RESET}")
        } else {
            format!("{UNTRUSTED_PREFIX}{sanitized}")
        };

        out.write_all(sanitized_untrusted_prefix.as_bytes())
            .context("Failed to write sanitized output")?;
        out.flush().context("Failed to flush sanitized output")?;
    }

    Ok(())
}

/// Convert a document to raw RGB pixel data using the Dangerzone container
pub fn convert_doc_to_pixels(input_path: String) -> Result<Vec<u8>> {
    eprintln!("Converting document to pixels...");

    let mut args = vec!["run".to_string()];
    args.extend(get_security_args());
    args.extend(vec![
        "--rm".to_string(),
        "-i".to_string(),
        IMAGE_NAME.to_string(),
        "/usr/bin/python3".to_string(),
        "-m".to_string(),
        "dangerzone.conversion.doc_to_pixels".to_string(),
    ]);

    let mut child = Command::new("podman")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(format!(
            "Failed to spawn container. Make sure podman is installed and the image '{IMAGE_NAME}' is pulled."
        ))?;

    // Take ownership of child stderr pipe and output sanitized text to parent stderr
    let stderr = child
        .stderr
        .take()
        .context("Failed to take ownership of stderr")?;
    let stderr_thread = std::thread::spawn(move || -> Result<()> {
        forward_sanitized_text(BufReader::new(stderr), std::io::stderr().lock())
    });

    // Read the input document
    let mut input_file = File::open(&input_path).context(format!(
        "Failed to open input file '{input_path_sanitized}'",
        input_path_sanitized = replace_control_chars(&input_path, false)
    ))?;
    let mut input_data = Vec::new();
    input_file
        .read_to_end(&mut input_data)
        .context("Failed to read input file")?;

    // Write the document to the container's stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&input_data)
            .context("Failed to write to container stdin")?;
    }

    // Read the output from the container
    let output = child
        .wait_with_output()
        .context("Failed to wait for container")?;

    // Read stderr from the container
    match stderr_thread.join() {
        Err(_) => {
            eprintln!("Warning: stderr_thread panicked while forwarding container stderr");
        }
        Ok(Err(e)) => {
            eprintln!(
                "Warning: Failed to forward container stderr: {err_sanitized}",
                err_sanitized = replace_control_chars(&e.to_string(), true)
            );
        }
        Ok(Ok(_)) => {}
    }

    if !output.status.success() {
        anyhow::bail!(
            "Container failed with status: {}. The document format may be unsupported or corrupted.",
            output.status
        );
    }

    eprintln!("Document converted to pixels successfully");
    Ok(output.stdout)
}

/// Convert pixel data to a PDF file
pub fn pixels_to_pdf(pages: Vec<PageData>, output_path: String) -> Result<()> {
    eprintln!("Converting pixels to safe PDF...");

    write_pages_to_pdf_file(&pages, None, &output_path, "Failed to write PDF")?;

    eprintln!(
        "Safe PDF created successfully at: {output_path_sanitized}",
        output_path_sanitized = replace_control_chars(&output_path, false)
    );
    Ok(())
}

/// Convert pixel data to a PDF file and add the provided OCR text layer
fn pixels_to_pdf_with_ocr(
    pages: &[PageData],
    ocr_pages: &[ocr::OcrPage],
    output_path: &str,
) -> Result<()> {
    eprintln!("Converting pixels to safe PDF with OCR text layer...");

    write_pages_to_pdf_file(
        pages,
        Some(ocr_pages),
        output_path,
        "Failed to write PDF with OCR",
    )?;

    eprintln!(
        "Safe PDF with OCR created successfully at: {output_path_sanitized}",
        output_path_sanitized = replace_control_chars(output_path, false)
    );
    Ok(())
}

fn write_pages_to_pdf_file(
    pages: &[PageData],
    ocr_pages: Option<&[ocr::OcrPage]>,
    output_path: &str,
    write_context: &'static str,
) -> Result<()> {
    if pages.is_empty() {
        anyhow::bail!("No pages to convert");
    }

    let pdf_data = build_pdf(pages, ocr_pages);
    let mut file = File::create(output_path).context(format!(
        "Failed to create output file '{output_path_sanitized}'",
        output_path_sanitized = replace_control_chars(output_path, false)
    ))?;
    file.write_all(&pdf_data).context(write_context)
}

/// Convert a document to a safe PDF in one call
pub fn convert_document(input_path: String, output_path: String, apply_ocr: bool) -> Result<()> {
    if apply_ocr {
        return apply_ocr_fn(input_path, output_path);
    }

    let pixels_data = convert_doc_to_pixels(input_path)?;
    let pages = parse_pixel_data(&pixels_data)?;

    pixels_to_pdf(pages, output_path).context("Failed to convert pixels to PDF")
}

/// Compress data with zlib, for a PDF `/FlateDecode` stream.
fn zlib_compress(data: &[u8]) -> Vec<u8> {
    // The encoder only fails if its writer fails, and writing to a `Vec`
    // never does.
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .expect("compressing into a Vec can't fail");
    encoder.finish().expect("compressing into a Vec can't fail")
}

/// Build a minimal PDF file with embedded RGB pixel data
fn build_pdf(pages: &[PageData], ocr_pages: Option<&[ocr::OcrPage]>) -> Vec<u8> {
    if let Some(ocr_pages) = ocr_pages {
        if ocr_pages.len() != pages.len() {
            panic!(
                "OCR page count ({}) does not match PDF page count ({})",
                ocr_pages.len(),
                pages.len()
            );
        }
    }
    let mut pdf_data = Vec::new();
    let mut object_offsets = Vec::new();
    let has_ocr = ocr_pages.is_some();

    // If OCR is used, objects 3 - 6 are used for embedding the OCR glyphless font.
    // For pure image based documents, the first object is still located at index 3.
    let first_object_on_first_page_index = if has_ocr { 7 } else { 3 };

    // PDF Header
    pdf_data.extend_from_slice(b"%PDF-1.4\n");
    pdf_data.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

    // Object 1: Catalog
    object_offsets.push(pdf_data.len());
    pdf_data.extend_from_slice(b"1 0 obj\n");
    pdf_data.extend_from_slice(b"<<\n");
    pdf_data.extend_from_slice(b"/Type /Catalog\n");
    pdf_data.extend_from_slice(b"/Pages 2 0 R\n");
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"endobj\n");

    // Object 2: Pages (parent)
    object_offsets.push(pdf_data.len());
    pdf_data.extend_from_slice(b"2 0 obj\n");
    pdf_data.extend_from_slice(b"<<\n");
    pdf_data.extend_from_slice(b"/Type /Pages\n");

    // Build kids array
    let mut kids = String::from("/Kids [");
    for i in 0..pages.len() {
        // Dynamically reference first `/Type /Page` object depending on if OCR is used.
        kids.push_str(&format!(
            "{} 0 R ",
            first_object_on_first_page_index + i * 2
        ));
    }
    kids.push_str("]\n");
    pdf_data.extend_from_slice(kids.as_bytes());

    pdf_data.extend_from_slice(format!("/Count {}\n", pages.len()).as_bytes());
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"endobj\n");

    // If OCR is used, embed our OCR font objects into the PDF.
    if has_ocr {
        ocr::pdf_renderer::embed_ocr_font(&mut pdf_data, &mut object_offsets);
    }

    let first_content_object_index_curr_page = first_object_on_first_page_index + pages.len() * 2;

    // For each page, create a Page object and an Image XObject
    for (page_idx, page) in pages.iter().enumerate() {
        eprintln!("Adding page {} to PDF...", page_idx + 1);

        // Convert pixels to points (1 point = 1/72 inch)
        let width_pts = (page.width as f32) / (DPI as f32) * 72.0;
        let height_pts = (page.height as f32) / (DPI as f32) * 72.0;

        // Page object
        let page_obj_num = first_object_on_first_page_index + page_idx * 2;
        let image_obj_num = page_obj_num + 1;

        object_offsets.push(pdf_data.len());
        pdf_data.extend_from_slice(format!("{page_obj_num} 0 obj\n").as_bytes());
        pdf_data.extend_from_slice(b"<<\n");
        pdf_data.extend_from_slice(b"/Type /Page\n");
        pdf_data.extend_from_slice(b"/Parent 2 0 R\n");
        pdf_data.extend_from_slice(
            format!("/MediaBox [0 0 {width_pts:.2} {height_pts:.2}]\n").as_bytes(),
        );
        pdf_data.extend_from_slice(b"/Resources <<\n");
        pdf_data.extend_from_slice(
            format!("  /XObject << /Im{page_idx} {image_obj_num} 0 R >>\n").as_bytes(),
        );

        // If OCR is used reference to object 3 containing the Type0 font as used font.
        if has_ocr {
            pdf_data.extend_from_slice(b"  /Font << /OcrFont 3 0 R >>\n");
        }

        pdf_data.extend_from_slice(b">>\n");

        // Reference to content stream object
        pdf_data.extend_from_slice(
            format!(
                "/Contents {} 0 R\n",
                first_content_object_index_curr_page + page_idx
            )
            .as_bytes(),
        );
        pdf_data.extend_from_slice(b">>\n");
        pdf_data.extend_from_slice(b"endobj\n");

        // Image XObject
        object_offsets.push(pdf_data.len());
        pdf_data.extend_from_slice(format!("{image_obj_num} 0 obj\n").as_bytes());
        pdf_data.extend_from_slice(b"<<\n");
        pdf_data.extend_from_slice(b"/Type /XObject\n");
        pdf_data.extend_from_slice(b"/Subtype /Image\n");
        pdf_data.extend_from_slice(format!("/Width {}\n", page.width).as_bytes());
        pdf_data.extend_from_slice(format!("/Height {}\n", page.height).as_bytes());
        pdf_data.extend_from_slice(b"/ColorSpace /DeviceRGB\n");
        pdf_data.extend_from_slice(b"/BitsPerComponent 8\n");

        // Compress pixel data using Flate compression
        let compressed_pixels = zlib_compress(&page.pixels);

        pdf_data.extend_from_slice(b"/Filter /FlateDecode\n");
        pdf_data.extend_from_slice(format!("/Length {}\n", compressed_pixels.len()).as_bytes());
        pdf_data.extend_from_slice(b">>\n");
        pdf_data.extend_from_slice(b"stream\n");
        pdf_data.extend_from_slice(&compressed_pixels);
        pdf_data.extend_from_slice(b"\nendstream\n");
        pdf_data.extend_from_slice(b"endobj\n");
    }

    // Content stream objects for each page
    for (page_idx, page) in pages.iter().enumerate() {
        let width_pts = (page.width as f32) / (DPI as f32) * 72.0;
        let height_pts = (page.height as f32) / (DPI as f32) * 72.0;
        let mut content =
            format!("q\n{width_pts:.2} 0 0 {height_pts:.2} 0 0 cm\n/Im{page_idx} Do\nQ\n");

        if let Some(ocr_page) = ocr_pages.and_then(|pages| pages.get(page_idx)) {
            ocr::pdf_renderer::append_ocr_text_layer(&mut content, ocr_page, height_pts);
        }

        let content_obj_num = first_content_object_index_curr_page + page_idx;
        object_offsets.push(pdf_data.len());
        pdf_data.extend_from_slice(format!("{content_obj_num} 0 obj\n").as_bytes());
        pdf_data.extend_from_slice(b"<<\n");
        pdf_data.extend_from_slice(format!("/Length {}\n", content.len()).as_bytes());
        pdf_data.extend_from_slice(b">>\n");
        pdf_data.extend_from_slice(b"stream\n");
        pdf_data.extend_from_slice(content.as_bytes());
        pdf_data.extend_from_slice(b"\nendstream\n");
        pdf_data.extend_from_slice(b"endobj\n");
    }

    // Cross-reference table
    let xref_offset = pdf_data.len();
    let num_objects = object_offsets.len();
    pdf_data.extend_from_slice(b"xref\n");
    pdf_data.extend_from_slice(format!("0 {}\n", num_objects + 1).as_bytes());
    pdf_data.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &object_offsets {
        pdf_data.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }

    // Trailer
    pdf_data.extend_from_slice(b"trailer\n");
    pdf_data.extend_from_slice(b"<<\n");
    pdf_data.extend_from_slice(format!("/Size {}\n", num_objects + 1).as_bytes());
    pdf_data.extend_from_slice(b"/Root 1 0 R\n");
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"startxref\n");
    pdf_data.extend_from_slice(format!("{xref_offset}\n").as_bytes());
    pdf_data.extend_from_slice(b"%%EOF\n");

    pdf_data
}

/// Convert a document to a safe PDF and add an OCR text layer.
// TODO: When having the implementations for Apple Vision and windows.media.ocr
// I want to use conditional compilation flags to dynamically set the OCR backend.
// This way `apply_ocr_fn` should be platform aware.
pub fn apply_ocr_fn(input_path: String, output_path: String) -> Result<()> {
    eprintln!("Applying OCR with integrated backend...");

    let pixels_data = convert_doc_to_pixels(input_path)?;
    let pages = parse_pixel_data(&pixels_data)?;

    let backend = KreuzbergTesseractOcr::new();
    let ocr_pages = backend
        .ocr_pages(&pages)
        .context("Failed to run OCR backend")?;

    pixels_to_pdf_with_ocr(&pages, &ocr_pages, &output_path)
        .context("Failed to convert pixels to OCR PDF")
}

/// Python bindings module
/// Re-exports from the python module to make them available to PyO3
#[cfg(feature = "python")]
pub mod python;

#[cfg(test)]
mod tests {
    use std::fs;

    use testresult::TestResult;

    use super::*;

    #[test]
    fn test_page_size_calculation() {
        let width_pixels = 1500u16;
        let height_pixels = 2000u16;
        let dpi = 150.0f32;

        let width_mm = (width_pixels as f32) / dpi * 25.4;
        let height_mm = (height_pixels as f32) / dpi * 25.4;

        assert_eq!(width_mm, 254.0);
        assert_eq!(height_mm, 338.66666);
    }

    #[test]
    fn test_pixel_data_parsing() -> TestResult {
        let mut data = Vec::new();

        let page_count: u16 = 1;
        data.extend_from_slice(&page_count.to_be_bytes());

        let width: u16 = 100;
        let height: u16 = 50;
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());

        let num_pixels = (width as usize) * (height as usize) * 3;
        data.extend(vec![128u8; num_pixels]);

        let pages = parse_pixel_data(&data)?;
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].width(), width);
        assert_eq!(pages[0].height(), height);
        assert_eq!(pages[0].pixels().len(), num_pixels);
        Ok(())
    }

    /// Build a pixel stream with the given page count and `(width, height)`
    /// headers, filling each page with the right amount of pixel bytes.
    fn pixel_stream(page_count: u16, dims: &[(u16, u16)]) -> Vec<u8> {
        let mut data = page_count.to_be_bytes().to_vec();
        for &(width, height) in dims {
            data.extend_from_slice(&width.to_be_bytes());
            data.extend_from_slice(&height.to_be_bytes());
            data.resize(data.len() + width as usize * height as usize * 3, 0);
        }
        data
    }

    fn parse_err(data: &[u8]) -> PixelDataError {
        parse_pixel_data(data).unwrap_err()
    }

    #[test]
    fn test_pixel_data_parsing_multiple_pages() -> TestResult {
        let pages = parse_pixel_data(&pixel_stream(2, &[(3, 2), (1, 5)]))?;
        let dims: Vec<_> = pages.iter().map(|p| (p.width(), p.height())).collect();
        assert_eq!(dims, [(3, 2), (1, 5)]);
        assert_eq!(pages[1].pixels().len(), 15);
        Ok(())
    }

    #[test]
    fn test_pixel_data_rejects_bad_page_count() {
        assert!(matches!(parse_err(&[]), PixelDataError::MissingPageCount));
        assert!(matches!(parse_err(&[0]), PixelDataError::MissingPageCount));
        assert!(matches!(
            parse_err(&pixel_stream(0, &[])),
            PixelDataError::NoPages
        ));
        assert!(matches!(
            parse_err(&pixel_stream(MAX_PAGES + 1, &[])),
            PixelDataError::TooManyPages(n) if n == MAX_PAGES + 1
        ));
    }

    #[test]
    fn test_pixel_data_rejects_bad_dimensions() {
        for dims in [
            (0, 10),
            (10, 0),
            (MAX_PAGE_WIDTH + 1, 1),
            (1, MAX_PAGE_HEIGHT + 1),
        ] {
            // Only the header matters, the parser must stop before the pixels.
            let mut data = 1u16.to_be_bytes().to_vec();
            data.extend_from_slice(&dims.0.to_be_bytes());
            data.extend_from_slice(&dims.1.to_be_bytes());
            let (width, height) = dims;
            assert!(
                matches!(
                    parse_err(&data),
                    PixelDataError::InvalidPage {
                        page: 1,
                        source: PageError::InvalidDimensions { .. },
                    }
                ),
                "dimensions {width}x{height} should be rejected"
            );
        }
    }

    #[test]
    fn test_pixel_data_accepts_maximum_dimensions() -> TestResult {
        let pages = parse_pixel_data(&pixel_stream(
            2,
            &[(MAX_PAGE_WIDTH, 1), (1, MAX_PAGE_HEIGHT)],
        ))?;
        assert_eq!(pages.len(), 2);
        Ok(())
    }

    #[test]
    fn test_pixel_data_rejects_truncated_data() {
        let full = pixel_stream(2, &[(2, 2), (2, 2)]);
        // Page 1 takes bytes 2..18. Cut inside each field of page 2.
        for (cut, expected) in [
            (19, CorruptedPageField::Width),
            (21, CorruptedPageField::Height),
            (25, CorruptedPageField::Pixels),
        ] {
            let err = parse_err(&full[..cut]);
            assert!(
                matches!(err, PixelDataError::Truncated { page: 2, field } if field == expected),
                "cut at {cut}: unexpected error {err:?}"
            );
        }
        assert!(parse_pixel_data(&full).is_ok());
    }

    #[test]
    fn test_pixel_data_rejects_trailing_data() {
        let mut data = pixel_stream(1, &[(1, 1)]);
        data.push(0);
        assert!(matches!(parse_err(&data), PixelDataError::TrailingData(1)));
    }

    #[test]
    fn test_page_data_new_checks_invariants() {
        assert!(PageData::new(2, 2, vec![0; 12]).is_ok());
        for len in [11, 13] {
            assert_eq!(
                PageData::new(2, 2, vec![0; len]).unwrap_err(),
                PageError::PixelLength {
                    width: 2,
                    height: 2,
                    expected: 12,
                    actual: len
                }
            );
        }
        assert_eq!(
            PageData::new(0, 2, vec![]).unwrap_err(),
            PageError::InvalidDimensions {
                width: 0,
                height: 2
            }
        );
        assert!(matches!(
            PageData::new(MAX_PAGE_WIDTH + 1, 1, vec![0; 30003]),
            Err(PageError::InvalidDimensions { .. })
        ));
    }

    #[test]
    fn test_pdf_generation() -> TestResult {
        let width = 10u16;
        let height = 10u16;
        let mut pixels = Vec::new();

        for _ in 0..(width * height) {
            pixels.push(255);
            pixels.push(0);
            pixels.push(0);
        }

        let page = PageData::new(width, height, pixels)?;
        let pages = vec![page];

        let pdf_data = build_pdf(&pages, None);
        assert!(!pdf_data.is_empty(), "PDF should have data");

        let header = String::from_utf8_lossy(&pdf_data[0..9]);
        assert!(
            header.starts_with("%PDF-1.4"),
            "PDF should have correct header"
        );

        let trailer = String::from_utf8_lossy(&pdf_data);
        assert!(trailer.contains("%%EOF"), "PDF should have EOF marker");
        assert!(
            trailer.contains("/Type /Catalog"),
            "PDF should have catalog"
        );
        assert!(trailer.contains("/Type /Pages"), "PDF should have pages");
        assert!(
            trailer.contains("/Type /Page"),
            "PDF should have page object"
        );
        assert!(
            trailer.contains("/Type /XObject"),
            "PDF should have image object"
        );

        assert!(
            trailer.contains("/Filter /FlateDecode"),
            "PDF should use Flate compression for images"
        );
        Ok(())
    }

    #[test]
    fn test_pdf_compression_reduces_size() -> TestResult {
        let width = 100u16;
        let height = 100u16;
        let mut pixels = Vec::new();

        for _ in 0..(width * height) {
            pixels.push(255);
            pixels.push(0);
            pixels.push(0);
        }

        let page = PageData::new(width, height, pixels.clone())?;
        let pages = vec![page];

        let pdf_data = build_pdf(&pages, None);

        let uncompressed_pixel_size = pixels.len();
        assert_eq!(uncompressed_pixel_size, 30000);

        let estimated_uncompressed_pdf_size = uncompressed_pixel_size + 1000;

        eprintln!("PDF size with compression: {} bytes", pdf_data.len());
        eprintln!("Estimated uncompressed size: {estimated_uncompressed_pdf_size} bytes");
        eprintln!(
            "Compression ratio: {:.2}%",
            (pdf_data.len() as f32 / estimated_uncompressed_pdf_size as f32) * 100.0
        );

        assert!(
            pdf_data.len() < estimated_uncompressed_pdf_size / 2,
            "PDF with compression should be significantly smaller than uncompressed"
        );
        Ok(())
    }

    #[test]
    fn test_pdf_generation_with_hidden_ocr_text() -> TestResult {
        let width = 10u16;
        let height = 10u16;
        let page = PageData::new(
            width,
            height,
            vec![255; width as usize * height as usize * 3],
        )?;
        let pages = vec![page];
        let ocr_pages = vec![ocr::OcrPage::from_test_words(vec![(
            "hello (pdf)",
            1,
            2,
            3,
            4,
        )])];

        let pdf_data = build_pdf(&pages, Some(&ocr_pages));
        let pdf_data = String::from_utf8_lossy(&pdf_data).into_owned();
        assert!(
            pdf_data.contains("/Font << /OcrFont"),
            "PDF should include OCR font resource"
        );
        assert!(
            pdf_data.contains("3 Tr"),
            "PDF should use invisible text rendering mode"
        );
        assert!(
            pdf_data.contains("<00680065006C006C006F002000280070006400660029> Tj"),
            "PDF should contain UTF-16BE hex OCR text"
        );
        assert!(
            pdf_data.contains(" Tz\n"),
            "PDF should set horizontal text scaling for OCR width alignment"
        );

        // Verify that each /Contents reference points to an existing object.
        let mut content_refs = Vec::new();
        for line in pdf_data.lines() {
            if let Some(rest) = line.strip_prefix("/Contents ") {
                let obj_num: usize = rest
                    .split_whitespace()
                    .next()
                    .ok_or("missing contents object number")?
                    .parse()?;
                content_refs.push(obj_num);
            }
        }
        assert!(
            !content_refs.is_empty(),
            "PDF should include /Contents references"
        );
        for obj_num in content_refs {
            assert!(
                pdf_data.contains(&format!("{obj_num} 0 obj")),
                "Missing content object for /Contents reference: {obj_num} 0 R"
            );
        }
        Ok(())
    }

    #[test]
    fn test_forward_sanitized_text() -> TestResult {
        let input = concat!(
            "plain ✓ café 😀\n",
            "\x1b[31mANSI escaped\n",
            "red text.\x1b[0m\n",
            "\ttab\rline\n",
            "a\u{200E}b\u{E000}c\u{0378}d\u{2028}e\u{2029}f\n",
            "x\n",
            "\u{2028}\u{2029}y\n",
            "ok line\n",
            "\x1b[31mred\x1b[0m\n",
            "end",
        );
        let expected_output = concat!(
            "UNTRUSTED> plain ✓ café 😀\n",
            "UNTRUSTED> \u{FFFD}[31mANSI escaped\n",
            "UNTRUSTED> red text.\u{FFFD}[0m\n",
            "UNTRUSTED> \u{FFFD}tab\u{FFFD}line\n",
            "UNTRUSTED> a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f\n",
            "UNTRUSTED> x\n",
            "UNTRUSTED> \u{FFFD}\u{FFFD}y\n",
            "UNTRUSTED> ok line\n",
            "UNTRUSTED> \u{FFFD}[31mred\u{FFFD}[0m\n",
            "UNTRUSTED> end\n",
        );

        let reader = BufReader::new(std::io::Cursor::new(input.as_bytes()));
        let out = tempfile::NamedTempFile::new()?;
        let out_path = out.path().to_path_buf();
        let out_file = out.reopen()?;

        forward_sanitized_text(reader, out_file)?;

        let output_bytes = fs::read(out_path)?;
        let output = String::from_utf8(output_bytes)?;
        assert_eq!(
            output, expected_output,
            "forward_sanitized_text failed for input: {input:?}",
        );
        Ok(())
    }
}
