use anyhow::{Context, Result};
use clap::Parser;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// A simple Dangerzone CLI implementation in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input document path
    #[arg(short, long)]
    input: String,

    /// Output PDF path
    #[arg(short, long)]
    output: String,

    /// Enable OCR to add text layer to PDF
    #[arg(long, default_value = "false")]
    ocr: bool,
}

const IMAGE_NAME: &str = "ghcr.io/freedomofpress/dangerzone/v1";
const INT_BYTES: usize = 2;
const DPI: f32 = 150.0;

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

struct PageData {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
}

fn parse_pixel_data(data: &[u8]) -> Result<Vec<PageData>> {
    let mut pos = 0;

    // Read page count
    if data.len() < INT_BYTES {
        anyhow::bail!("Insufficient data for page count");
    }
    let page_count = read_u16_be(&data[pos..pos + INT_BYTES])?;
    pos += INT_BYTES;

    eprintln!("Document has {} page(s)", page_count);

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

fn convert_doc_to_pixels(input_path: &str) -> Result<Vec<u8>> {
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
        .with_context(|| {
            format!(
                "Failed to spawn container. Make sure podman is installed and the image '{}' is pulled.",
                IMAGE_NAME
            )
        })?;

    // Read the input document
    let mut input_file = File::open(input_path).context("Failed to open input file")?;
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

fn convert_pixels_to_pdf(pages: &[PageData], output_path: &str, _enable_ocr: bool) -> Result<()> {
    eprintln!("Converting pixels to safe PDF...");

    if pages.is_empty() {
        anyhow::bail!("No pages to convert");
    }

    let mut file = File::create(output_path).context("Failed to create output file")?;
    write_pdf(&mut file, pages)?;

    eprintln!("Safe PDF created successfully at: {}", output_path);
    Ok(())
}

/// Write a minimal PDF file with embedded RGB pixel data
fn write_pdf(writer: &mut File, pages: &[PageData]) -> Result<()> {
    // PDF structure:
    // 1. Header
    // 2. Objects (catalog, pages, page objects, image objects)
    // 3. Cross-reference table (xref)
    // 4. Trailer
    
    let mut pdf_data = Vec::new();
    let mut object_offsets = Vec::new();
    
    // PDF Header
    pdf_data.extend_from_slice(b"%PDF-1.4\n");
    pdf_data.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n"); // Binary comment for compatibility
    
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
        pdf_data.extend_from_slice(format!("{} 0 obj\n", page_obj_num).as_bytes());
        pdf_data.extend_from_slice(b"<<\n");
        pdf_data.extend_from_slice(b"/Type /Page\n");
        pdf_data.extend_from_slice(b"/Parent 2 0 R\n");
        pdf_data.extend_from_slice(format!("/MediaBox [0 0 {:.2} {:.2}]\n", width_pts, height_pts).as_bytes());
        pdf_data.extend_from_slice(b"/Resources <<\n");
        pdf_data.extend_from_slice(format!("  /XObject << /Im{} {} 0 R >>\n", page_idx, image_obj_num).as_bytes());
        pdf_data.extend_from_slice(b">>\n");
        
        // Reference to content stream object
        pdf_data.extend_from_slice(format!("/Contents {} 0 R\n", 3 + pages.len() * 2 + page_idx).as_bytes());
        pdf_data.extend_from_slice(b">>\n");
        pdf_data.extend_from_slice(b"endobj\n");
        
        // Image XObject
        object_offsets.push(pdf_data.len());
        pdf_data.extend_from_slice(format!("{} 0 obj\n", image_obj_num).as_bytes());
        pdf_data.extend_from_slice(b"<<\n");
        pdf_data.extend_from_slice(b"/Type /XObject\n");
        pdf_data.extend_from_slice(b"/Subtype /Image\n");
        pdf_data.extend_from_slice(format!("/Width {}\n", page.width).as_bytes());
        pdf_data.extend_from_slice(format!("/Height {}\n", page.height).as_bytes());
        pdf_data.extend_from_slice(b"/ColorSpace /DeviceRGB\n");
        pdf_data.extend_from_slice(b"/BitsPerComponent 8\n");
        pdf_data.extend_from_slice(format!("/Length {}\n", page.pixels.len()).as_bytes());
        pdf_data.extend_from_slice(b">>\n");
        pdf_data.extend_from_slice(b"stream\n");
        pdf_data.extend_from_slice(&page.pixels);
        pdf_data.extend_from_slice(b"\nendstream\n");
        pdf_data.extend_from_slice(b"endobj\n");
    }
    
    // Content stream objects for each page
    for (page_idx, page) in pages.iter().enumerate() {
        let width_pts = (page.width as f32) / DPI * 72.0;
        let height_pts = (page.height as f32) / DPI * 72.0;
        let content = format!("q\n{:.2} 0 0 {:.2} 0 0 cm\n/Im{} Do\nQ\n", width_pts, height_pts, page_idx);
        
        let content_obj_num = 3 + pages.len() * 2 + page_idx;
        object_offsets.push(pdf_data.len());
        pdf_data.extend_from_slice(format!("{} 0 obj\n", content_obj_num).as_bytes());
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
        pdf_data.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
    }
    
    // Trailer
    pdf_data.extend_from_slice(b"trailer\n");
    pdf_data.extend_from_slice(b"<<\n");
    pdf_data.extend_from_slice(format!("/Size {}\n", num_objects + 1).as_bytes());
    pdf_data.extend_from_slice(b"/Root 1 0 R\n");
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"startxref\n");
    pdf_data.extend_from_slice(format!("{}\n", xref_offset).as_bytes());
    pdf_data.extend_from_slice(b"%%EOF\n");
    
    writer.write_all(&pdf_data).context("Failed to write PDF data")?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("Dangerzone Rust CLI");
    eprintln!("Using container runtime: podman");
    eprintln!("Input: {}", args.input);
    eprintln!("Output: {}", args.output);
    if args.ocr {
        eprintln!("OCR: enabled");
    }
    eprintln!();

    let pixels_data = convert_doc_to_pixels(&args.input)?;
    let pages = parse_pixel_data(&pixels_data)?;

    let temp_output = if args.ocr {
        format!("{}.temp.pdf", args.output)
    } else {
        args.output.clone()
    };

    convert_pixels_to_pdf(&pages, &temp_output, false)?;

    if args.ocr {
        apply_ocr(&temp_output, &args.output)?;
        std::fs::remove_file(&temp_output).context("Failed to remove temporary file")?;
    }

    eprintln!();
    eprintln!("Conversion completed successfully!");
    eprintln!("Processed {} page(s)", pages.len());
    Ok(())
}

fn apply_ocr(input_pdf: &str, output_pdf: &str) -> Result<()> {
    eprintln!("Applying OCR to PDF...");

    let output = Command::new("ocrmypdf")
        .args([
            "--skip-text", // Skip pages that already have text
            "--force-ocr", // Force OCR on all pages
            input_pdf,
            output_pdf,
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            eprintln!("OCR applied successfully");
            Ok(())
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            eprintln!("Warning: OCR failed: {}", stderr);
            eprintln!("Falling back to PDF without OCR");
            std::fs::copy(input_pdf, output_pdf).context("Failed to copy PDF")?;
            Ok(())
        }
        Err(e) => {
            eprintln!("Warning: ocrmypdf not found or failed: {}", e);
            eprintln!("Falling back to PDF without OCR");
            eprintln!("To enable OCR, install ocrmypdf: pip install ocrmypdf");
            std::fs::copy(input_pdf, output_pdf).context("Failed to copy PDF")?;
            Ok(())
        }
    }
}

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

        let result = parse_pixel_data(&data);
        assert!(result.is_ok());

        let pages = result.unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].width, width);
        assert_eq!(pages[0].height, height);
        assert_eq!(pages[0].pixels.len(), num_pixels);
    }
}
