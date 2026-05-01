use anyhow::{Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use util::replace_control_chars;

mod ocr;
mod util;

pub use ocr::{OcrBackend, OcrEngine, OcrTextLayer, OcrWord, TesseractOcrEngine};

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

    write_pdf_file(&pages, &output_path).context("Failed to write PDF")?;

    eprintln!(
        "Safe PDF created successfully at: {output_path_sanitized}",
        output_path_sanitized = replace_control_chars(&output_path, false)
    );
    Ok(())
}

/// Convert a document to a safe PDF in one call
pub fn convert_document(input_path: String, output_path: String, apply_ocr: bool) -> Result<()> {
    convert_document_with_ocr_backend(input_path, output_path, apply_ocr, OcrBackend::Kreuzberg)
}

/// Convert a document to a safe PDF in one call, with selectable OCR backend.
pub fn convert_document_with_ocr_backend(
    input_path: String,
    output_path: String,
    apply_ocr: bool,
    ocr_backend: OcrBackend,
) -> Result<()> {
    let pixels_data = convert_doc_to_pixels(input_path)?;
    let pages = parse_pixel_data(pixels_data)?;

    if !apply_ocr {
        return pixels_to_pdf(pages, output_path);
    }

    match ocr_backend {
        OcrBackend::Kreuzberg => {
            eprintln!("Recognizing page pixels with Kreuzberg backend...");
            let ocr_engine = TesseractOcrEngine::from_env();
            match write_pdf_with_ocr_text(&pages, &output_path, &ocr_engine) {
                Ok(()) => {
                    eprintln!("OCR applied successfully using Kreuzberg");
                    Ok(())
                }
                Err(e) => {
                    eprintln!(
                        "Warning: OCR failed: {stderr_sanitized}",
                        stderr_sanitized = replace_control_chars(&e.to_string(), true)
                    );
                    eprintln!("Falling back to PDF without OCR");
                    pixels_to_pdf(pages, output_path)
                }
            }
        }
        OcrBackend::Ocrmypdf => {
            let temp_output = format!("{output_path}.temp.pdf");
            pixels_to_pdf(pages, temp_output.clone()).context("Failed to convert pixels to PDF")?;
            apply_ocr_with_backend(temp_output.clone(), output_path, ocr_backend)?;
            std::fs::remove_file(&temp_output).context("Failed to remove temporary file")?;
            Ok(())
        }
    }
}

/// Write a minimal PDF file with embedded RGB pixel data
fn write_pdf<W: Write>(writer: &mut W, pages: &[PageData]) -> Result<()> {
    write_pdf_with_text_layers(writer, pages, None)
}

fn write_pdf_file(pages: &[PageData], output_path: &str) -> Result<()> {
    if pages.is_empty() {
        anyhow::bail!("No pages to convert");
    }

    let mut file = File::create(output_path).context(format!(
        "Failed to create output file '{output_path_sanitized}'",
        output_path_sanitized = replace_control_chars(output_path, false)
    ))?;
    write_pdf(&mut file, pages)
}

fn write_pdf_with_text_layers<W: Write>(
    writer: &mut W,
    pages: &[PageData],
    text_layers: Option<&[OcrTextLayer]>,
) -> Result<()> {
    let mut pdf_data = Vec::new();
    let mut object_offsets = Vec::new();

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
        kids.push_str(&format!("{} 0 R ", 4 + i * 2));
    }
    kids.push_str("]\n");
    pdf_data.extend_from_slice(kids.as_bytes());

    pdf_data.extend_from_slice(format!("/Count {}\n", pages.len()).as_bytes());
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"endobj\n");

    // Object 3: built-in font used only by the invisible OCR text layer.
    object_offsets.push(pdf_data.len());
    pdf_data.extend_from_slice(b"3 0 obj\n");
    pdf_data.extend_from_slice(b"<<\n");
    pdf_data.extend_from_slice(b"/Type /Font\n");
    pdf_data.extend_from_slice(b"/Subtype /Type1\n");
    pdf_data.extend_from_slice(b"/BaseFont /Helvetica\n");
    pdf_data.extend_from_slice(b"/Encoding /WinAnsiEncoding\n");
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"endobj\n");

    // For each page, create a Page object and an Image XObject
    for (page_idx, page) in pages.iter().enumerate() {
        eprintln!("Adding page {} to PDF...", page_idx + 1);

        // Convert pixels to points (1 point = 1/72 inch)
        let width_pts = (page.width as f32) / DPI * 72.0;
        let height_pts = (page.height as f32) / DPI * 72.0;

        // Page object
        let page_obj_num = 4 + page_idx * 2;
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
        pdf_data.extend_from_slice(b"  /Font << /F1 3 0 R >>\n");
        pdf_data.extend_from_slice(b">>\n");

        // Reference to content stream object
        pdf_data.extend_from_slice(
            format!("/Contents {} 0 R\n", 4 + pages.len() * 2 + page_idx).as_bytes(),
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
        if let Some(layers) = text_layers {
            if let Some(words) = layers.get(page_idx) {
                content.push_str(&build_text_layer(words, page.height));
            }
        }

        let content_obj_num = 4 + pages.len() * 2 + page_idx;
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

fn build_text_layer(words: &[OcrWord], page_height_px: u16) -> String {
    if words.is_empty() {
        return String::new();
    }

    let mut content = String::new();
    for word in words {
        let visual_text = pdf_escape_visible_text(&word.text);
        if visual_text.is_empty() {
            continue;
        }
        let actual_text = pdf_utf16be_hex_text(&word.text);

        let height = (word.bottom - word.top).max(1) as f32;
        let x = word.left.max(0) as f32 / DPI * 72.0;
        let y = (page_height_px as f32 - word.bottom.max(0) as f32) / DPI * 72.0;
        let font_size = (height / DPI * 72.0).max(1.0);
        let width = (word.right - word.left).max(1) as f32 / DPI * 72.0;
        let estimated_text_width = word.text.chars().count().max(1) as f32 * font_size * 0.5;
        let horizontal_scale = (width / estimated_text_width * 100.0).clamp(40.0, 200.0);

        content.push_str(&format!(
            "/Span << /ActualText <{actual_text}> >> BDC\nBT\n/F1 1 Tf\n3 Tr\n{font_size:.2} 0 0 {font_size:.2} {x:.2} {y:.2} Tm\n{horizontal_scale:.2} Tz\n({visual_text}) Tj\nET\nEMC\n"
        ));
    }
    content
}

fn pdf_escape_visible_text(text: &str) -> String {
    let mut escaped = String::new();
    for ch in text.chars() {
        match ch {
            '(' | ')' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '\n' | '\r' | '\t' => escaped.push(' '),
            ' '..='~' => escaped.push(ch),
            _ => escaped.push('?'),
        }
    }
    escaped
}

fn pdf_utf16be_hex_text(text: &str) -> String {
    let mut hex = String::with_capacity(4 + text.len() * 4);
    hex.push_str("FEFF");
    for unit in text.encode_utf16() {
        let _ = write!(&mut hex, "{unit:04X}");
    }
    hex
}

fn format_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}

/// Apply OCR to add an invisible text layer to a PDF generated by this crate.
pub fn apply_ocr_fn(input_pdf: String, output_pdf: String) -> Result<()> {
    apply_ocr_with_backend(input_pdf, output_pdf, OcrBackend::Ocrmypdf)
}

pub fn apply_ocr_with_backend(
    input_pdf: String,
    output_pdf: String,
    ocr_backend: OcrBackend,
) -> Result<()> {
    eprintln!("Applying OCR to PDF with {ocr_backend:?} backend...");

    if ocr_backend == OcrBackend::Kreuzberg {
        anyhow::bail!(
            "Kreuzberg OCR works from sanitized page pixels, not from a PDF path. Use convert_document(..., apply_ocr=true) or write_pdf_with_ocr_text()."
        );
    }

    let result = match ocr_backend {
        OcrBackend::Kreuzberg => unreachable!("handled before PDF OCR fallback"),
        OcrBackend::Ocrmypdf => apply_ocr_with_ocrmypdf(&input_pdf, &output_pdf),
    };

    match result {
        Ok(()) => {
            eprintln!("OCR applied successfully using {ocr_backend:?}");
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "Warning: OCR failed: {stderr_sanitized}",
                stderr_sanitized = replace_control_chars(&e.to_string(), true)
            );
            eprintln!("Falling back to PDF without OCR");
            std::fs::copy(&input_pdf, &output_pdf).context("Failed to copy PDF")?;
            Ok(())
        }
    }
}

fn apply_ocr_with_ocrmypdf(input_pdf: &str, output_pdf: &str) -> Result<()> {
    let started_at = Instant::now();
    let output = Command::new("ocrmypdf")
        .args([input_pdf, output_pdf])
        .output()
        .context("ocrmypdf not found or failed to start")?;
    let elapsed = started_at.elapsed();
    eprintln!("ocrmypdf OCR execution time: {}", format_duration(elapsed));

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "ocrmypdf failed: {stderr_sanitized}",
        stderr_sanitized = replace_control_chars(&stderr, true)
    )
}

pub fn write_pdf_with_ocr_text<E: OcrEngine>(
    pages: &[PageData],
    output_pdf: &str,
    ocr_engine: &E,
) -> Result<()> {
    let started_at = Instant::now();
    let text_layers = ocr_engine
        .recognize_pages(pages)
        .context("Failed to OCR page pixels")?;
    let elapsed = started_at.elapsed();
    eprintln!("OCR execution time: {}", format_duration(elapsed));

    let mut file = File::create(output_pdf).context(format!(
        "Failed to create OCR output file '{output_path_sanitized}'",
        output_path_sanitized = replace_control_chars(output_pdf, false)
    ))?;
    write_pdf_with_text_layers(&mut file, pages, Some(&text_layers))
        .context("Failed to write OCR text layer to PDF")?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_ocr_macos(input_pdf: &str, output_pdf: &str) -> Result<()> {
    eprintln!("Using macOS PDFKit for OCR...");

    let script_path = if let Ok(exe_path) = std::env::current_exe() {
        let mut path = exe_path.parent().unwrap().to_path_buf();
        path.push("macos_ocr.swift");
        if path.exists() {
            path
        } else {
            std::path::PathBuf::from("src/macos_ocr.swift")
        }
    } else {
        std::path::PathBuf::from("src/macos_ocr.swift")
    };

    if !script_path.exists() {
        anyhow::bail!("macOS OCR script not found at {:?}", script_path);
    }

    let input_absolute = std::fs::canonicalize(input_pdf).with_context(|| {
        format!(
            "Failed to get absolute path for input: {input_pdf_sanitized}",
            input_pdf_sanitized = replace_control_chars(input_pdf, false)
        )
    })?;
    let output_absolute = std::path::Path::new(output_pdf)
        .canonicalize()
        .unwrap_or_else(|_| {
            let output_path = std::path::Path::new(output_pdf);
            if output_path.is_absolute() {
                output_path.to_path_buf()
            } else {
                std::env::current_dir().unwrap().join(output_path)
            }
        });

    let output = Command::new("swift")
        .arg(&script_path)
        .arg(&input_absolute)
        .arg(&output_absolute)
        .output()
        .context("Failed to execute Swift OCR script")?;

    if output.status.success() {
        eprintln!("OCR applied successfully using macOS PDFKit");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Swift OCR script failed: {stderr_sanitized}",
            stderr_sanitized = replace_control_chars(&stderr, true)
        )
    }
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
        let result = write_pdf(buffer.get_mut(), &pages);
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
        let result = write_pdf(buffer.get_mut(), &pages);
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
    #[cfg(target_os = "macos")]
    fn test_macos_ocr_function_compiles() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_input = NamedTempFile::new().unwrap();
        temp_input.write_all(b"%PDF-1.4\n%%EOF\n").unwrap();
        let input_path = temp_input.path().to_str().unwrap();

        let temp_output = NamedTempFile::new().unwrap();
        let output_path = temp_output.path().to_str().unwrap();

        let result = apply_ocr_macos(input_path, output_path);
        assert!(result.is_err());
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
            "UNTRUSTED> end",
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
