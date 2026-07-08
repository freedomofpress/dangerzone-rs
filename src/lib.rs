// TODO: A library shouldn't use anyhow::Result. Use e.g thiserror instead.
use anyhow::{Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use ocr::OcrBackend;
use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::process::{Command, Stdio};
use util::replace_control_chars;

use crate::ocr::KreuzbergTesseractOcr;

mod ocr;
mod util;

pub const IMAGE_NAME: &str = "ghcr.io/freedomofpress/dangerzone/v1";
pub const INT_BYTES: usize = 2;
pub const DPI: f32 = 150.0;
const MAX_SANITIZED_CHUNK_BYTES: u64 = 64 * 1024;

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

fn read_u16_be(data: &[u8]) -> Result<u16> {
    if data.len() < INT_BYTES {
        anyhow::bail!("Not enough bytes to read u16");
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// Page data structure representing a single page's pixel information
#[derive(Clone)]
pub struct PageData {
    pub width: u16,
    pub height: u16,
    pub pixels: Vec<u8>,
}

impl PageData {
    pub fn new(width: u16, height: u16, pixels: Vec<u8>) -> Self {
        PageData {
            width,
            height,
            pixels,
        }
    }
}

/// Parse binary pixel data stream from the container
/// Returns a list of (width, height, pixel_data) tuples for each page
pub fn parse_pixel_data(data: Vec<u8>) -> Result<Vec<PageData>> {
    let mut pos = 0;

    // Read page count
    if data.len() < INT_BYTES {
        anyhow::bail!("Insufficient data for page count");
    }
    let page_count = read_u16_be(&data[pos..pos + INT_BYTES])?;
    pos += INT_BYTES;

    eprintln!("Document has {page_count} page(s)");

    let mut pages = Vec::new();

    for page_num in 0..page_count {
        // Read width
        if pos + INT_BYTES > data.len() {
            anyhow::bail!("Insufficient data for page {} width", page_num + 1);
        }
        let width = read_u16_be(&data[pos..pos + INT_BYTES])?;
        pos += INT_BYTES;

        // Read height
        if pos + INT_BYTES > data.len() {
            anyhow::bail!("Insufficient data for page {} height", page_num + 1);
        }
        let height = read_u16_be(&data[pos..pos + INT_BYTES])?;
        pos += INT_BYTES;

        eprintln!("Page {}: {}x{} pixels", page_num + 1, width, height);

        // Read pixel data (RGB, 3 bytes per pixel)
        let num_bytes = (width as usize) * (height as usize) * 3;
        if pos + num_bytes > data.len() {
            anyhow::bail!(
                "Insufficient data for page {} pixels (expected {} bytes)",
                page_num + 1,
                num_bytes
            );
        }

        let pixels = data[pos..pos + num_bytes].to_vec();
        pos += num_bytes;

        pages.push(PageData {
            width,
            height,
            pixels,
        });
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

        let s = String::from_utf8_lossy(&line_buf);
        let mut sanitized: String = replace_control_chars(&s, true);
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

    let mut file = File::create(output_path).context(format!(
        "Failed to create output file '{output_path_sanitized}'",
        output_path_sanitized = replace_control_chars(output_path, false)
    ))?;
    write_pdf(&mut file, pages, ocr_pages).context(write_context)
}

/// Convert a document to a safe PDF in one call
pub fn convert_document(input_path: String, output_path: String, apply_ocr: bool) -> Result<()> {
    if apply_ocr {
        return apply_ocr_fn(input_path, output_path);
    }

    let pixels_data = convert_doc_to_pixels(input_path)?;
    let pages = parse_pixel_data(pixels_data)?;

    pixels_to_pdf(pages, output_path).context("Failed to convert pixels to PDF")
}

/// Write a minimal PDF file with embedded RGB pixel data
fn write_pdf<W: Write>(
    writer: &mut W,
    pages: &[PageData],
    ocr_pages: Option<&[ocr::OcrPage]>,
) -> Result<()> {
    if let Some(ocr_pages) = ocr_pages {
        if ocr_pages.len() != pages.len() {
            anyhow::bail!(
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
        ocr::pdf_renderer::embed_ocr_font(&mut pdf_data, &mut object_offsets)?;
    }

    let first_content_object_index_curr_page = first_object_on_first_page_index + pages.len() * 2;

    // For each page, create a Page object and an Image XObject
    for (page_idx, page) in pages.iter().enumerate() {
        eprintln!("Adding page {} to PDF...", page_idx + 1);

        // Convert pixels to points (1 point = 1/72 inch)
        let width_pts = (page.width as f32) / DPI * 72.0;
        let height_pts = (page.height as f32) / DPI * 72.0;

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
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&page.pixels)
            .context("Failed to compress pixel data")?;
        let compressed_pixels = encoder.finish().context("Failed to finish compression")?;

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
        let width_pts = (page.width as f32) / DPI * 72.0;
        let height_pts = (page.height as f32) / DPI * 72.0;
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

    writer
        .write_all(&pdf_data)
        .context("Failed to write PDF data")?;
    Ok(())
}

/// Convert a document to a safe PDF and add an OCR text layer.
// TODO: When having the implementations for Apple Vision and windows.media.ocr
// I want to use conditional compilation flags to dynamically set the OCR backend.
// This way `apply_ocr_fn` should be platform aware.
pub fn apply_ocr_fn(input_path: String, output_path: String) -> Result<()> {
    eprintln!("Applying OCR with integrated backend...");

    let pixels_data = convert_doc_to_pixels(input_path)?;
    let pages = parse_pixel_data(pixels_data)?;

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
    fn test_pixel_data_parsing() {
        let mut data = Vec::new();

        let page_count: u16 = 1;
        data.extend_from_slice(&page_count.to_be_bytes());

        let width: u16 = 100;
        let height: u16 = 50;
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());

        let num_pixels = (width as usize) * (height as usize) * 3;
        data.extend(vec![128u8; num_pixels]);

        let result = parse_pixel_data(data);
        assert!(result.is_ok());

        let pages = result.unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].width, width);
        assert_eq!(pages[0].height, height);
        assert_eq!(pages[0].pixels.len(), num_pixels);
    }

    #[test]
    fn test_pdf_generation() {
        use std::io::Cursor;

        let width = 10u16;
        let height = 10u16;
        let mut pixels = Vec::new();

        for _ in 0..(width * height) {
            pixels.push(255);
            pixels.push(0);
            pixels.push(0);
        }

        let page = PageData {
            width,
            height,
            pixels,
        };
        let pages = vec![page];

        let mut buffer = Cursor::new(Vec::new());
        let result = write_pdf(buffer.get_mut(), &pages, None);
        assert!(result.is_ok(), "PDF generation should succeed");

        let pdf_data = buffer.into_inner();
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
    }

    #[test]
    fn test_pdf_compression_reduces_size() {
        use std::io::Cursor;

        let width = 100u16;
        let height = 100u16;
        let mut pixels = Vec::new();

        for _ in 0..(width * height) {
            pixels.push(255);
            pixels.push(0);
            pixels.push(0);
        }

        let page = PageData {
            width,
            height,
            pixels: pixels.clone(),
        };
        let pages = vec![page];

        let mut buffer = Cursor::new(Vec::new());
        let result = write_pdf(buffer.get_mut(), &pages, None);
        assert!(result.is_ok(), "PDF generation should succeed");

        let pdf_data = buffer.into_inner();

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
    }

    #[test]
    fn test_pdf_generation_with_hidden_ocr_text() {
        use std::io::Cursor;

        let width = 10u16;
        let height = 10u16;
        let page = PageData {
            width,
            height,
            pixels: vec![255; width as usize * height as usize * 3],
        };
        let pages = vec![page];
        let ocr_pages = vec![ocr::OcrPage::from_test_words(vec![(
            "hello (pdf)",
            1,
            2,
            3,
            4,
        )])];

        let mut buffer = Cursor::new(Vec::new());
        let result = write_pdf(buffer.get_mut(), &pages, Some(&ocr_pages));
        assert!(result.is_ok(), "PDF generation with OCR should succeed");

        let pdf_data = String::from_utf8_lossy(&buffer.into_inner()).into_owned();
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
                    .expect("contents object number")
                    .parse()
                    .expect("valid contents object number");
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
    }

    #[test]
    fn test_forward_sanitized_text() {
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
        let out = tempfile::NamedTempFile::new().unwrap();
        let out_path = out.path().to_path_buf();
        let out_file = out.reopen().unwrap();

        forward_sanitized_text(reader, out_file).unwrap();

        let output_bytes = std::fs::read(out_path).unwrap();
        let output = String::from_utf8(output_bytes).unwrap();
        assert_eq!(
            output, expected_output,
            "forward_sanitized_text failed for input: {input:?}",
        );
    }
}
