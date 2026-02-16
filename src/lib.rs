use anyhow::{Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

pub const IMAGE_NAME: &str = "ghcr.io/freedomofpress/dangerzone/v1";
pub const INT_BYTES: usize = 2;
pub const DPI: f32 = 150.0;

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
        .stderr(Stdio::inherit())
        .spawn()
        .context(format!(
            "Failed to spawn container. Make sure podman is installed and the image '{IMAGE_NAME}' is pulled."
        ))?;

    // Read the input document
    let mut input_file =
        File::open(&input_path).context(format!("Failed to open input file '{input_path}'"))?;
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

    if pages.is_empty() {
        anyhow::bail!("No pages to convert");
    }

    let mut file = File::create(&output_path)
        .context(format!("Failed to create output file '{output_path}'"))?;
    write_pdf(&mut file, &pages).context("Failed to write PDF")?;

    eprintln!("Safe PDF created successfully at: {output_path}");
    Ok(())
}

/// Convert a document to a safe PDF in one call
pub fn convert_document(input_path: String, output_path: String, apply_ocr: bool) -> Result<()> {
    let pixels_data = convert_doc_to_pixels(input_path)?;
    let pages = parse_pixel_data(pixels_data)?;

    let temp_output = if apply_ocr {
        format!("{output_path}.temp.pdf")
    } else {
        output_path.clone()
    };

    pixels_to_pdf(pages.clone(), temp_output.clone()).context("Failed to convert pixels to PDF")?;

    if apply_ocr {
        apply_ocr_fn(temp_output.clone(), output_path.clone())?;
        std::fs::remove_file(&temp_output).context("Failed to remove temporary file")?;
    }

    Ok(())
}

/// Write a minimal PDF file with embedded RGB pixel data
fn write_pdf<W: Write>(writer: &mut W, pages: &[PageData]) -> Result<()> {
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
        kids.push_str(&format!("{} 0 R ", 3 + i * 2));
    }
    kids.push_str("]\n");
    pdf_data.extend_from_slice(kids.as_bytes());

    pdf_data.extend_from_slice(format!("/Count {}\n", pages.len()).as_bytes());
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"endobj\n");

    // For each page, create a Page object and an Image XObject
    for (page_idx, page) in pages.iter().enumerate() {
        eprintln!("Adding page {} to PDF...", page_idx + 1);

        // Convert pixels to points (1 point = 1/72 inch)
        let width_pts = (page.width as f32) / DPI * 72.0;
        let height_pts = (page.height as f32) / DPI * 72.0;

        // Page object
        let page_obj_num = 3 + page_idx * 2;
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
        pdf_data.extend_from_slice(b">>\n");

        // Reference to content stream object
        pdf_data.extend_from_slice(
            format!("/Contents {} 0 R\n", 3 + pages.len() * 2 + page_idx).as_bytes(),
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
        let content =
            format!("q\n{width_pts:.2} 0 0 {height_pts:.2} 0 0 cm\n/Im{page_idx} Do\nQ\n");

        let content_obj_num = 3 + pages.len() * 2 + page_idx;
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

/// Apply OCR to add text layer to PDF (platform-aware)
pub fn apply_ocr_fn(input_pdf: String, output_pdf: String) -> Result<()> {
    eprintln!("Applying OCR to PDF...");

    // On macOS, try using PDFKit's saveTextFromOCROption first
    #[cfg(target_os = "macos")]
    {
        match apply_ocr_macos(&input_pdf, &output_pdf) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("Warning: macOS PDFKit OCR failed: {}", e);
                eprintln!("Falling back to ocrmypdf...");
            }
        }
    }

    // Fall back to ocrmypdf (for non-macOS or if PDFKit fails)
    let output = Command::new("ocrmypdf")
        .args(["--redo-ocr", &input_pdf, &output_pdf])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            eprintln!("OCR applied successfully");
            Ok(())
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            eprintln!("Warning: OCR failed: {stderr}");
            eprintln!("Falling back to PDF without OCR");
            std::fs::copy(&input_pdf, &output_pdf).context("Failed to copy PDF")?;
            Ok(())
        }
        Err(e) => {
            eprintln!("Warning: ocrmypdf not found or failed: {e}");
            eprintln!("Falling back to PDF without OCR");
            eprintln!("To enable OCR, install ocrmypdf: pip install ocrmypdf");
            std::fs::copy(&input_pdf, &output_pdf).context("Failed to copy PDF")?;
            Ok(())
        }
    }
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

    let input_absolute = std::fs::canonicalize(input_pdf)
        .with_context(|| format!("Failed to get absolute path for input: {}", input_pdf))?;
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
        anyhow::bail!("Swift OCR script failed: {}", stderr)
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
}
