use anyhow::{Context, Result};
use clap::Parser;
use printpdf::*;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::process::{Command, Stdio};

// Import image types with explicit prefix to avoid ambiguity
use ::image::{DynamicImage, ImageBuffer, Rgb};

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

fn convert_pixels_to_pdf(pages: &[PageData], output_path: &str) -> Result<()> {
    eprintln!("Converting pixels to safe PDF...");

    if pages.is_empty() {
        anyhow::bail!("No pages to convert");
    }

    // Create a new PDF document
    let first_page = &pages[0];
    let width_mm = (first_page.width as f32) / DPI * 25.4;
    let height_mm = (first_page.height as f32) / DPI * 25.4;

    let (doc, mut page_index, mut layer_index) =
        PdfDocument::new("Sanitized Document", Mm(width_mm), Mm(height_mm), "Layer 1");

    // Add first page image
    add_page_to_pdf(
        &doc,
        &mut page_index,
        &mut layer_index,
        &pages[0],
        width_mm,
        height_mm,
    )?;

    // Add remaining pages
    for (i, page) in pages.iter().enumerate().skip(1) {
        let width_mm = (page.width as f32) / DPI * 25.4;
        let height_mm = (page.height as f32) / DPI * 25.4;

        eprintln!("Adding page {} to PDF...", i + 1);

        // Add new page
        let (new_page_index, new_layer_index) =
            doc.add_page(Mm(width_mm), Mm(height_mm), "Layer 1");
        page_index = new_page_index;
        layer_index = new_layer_index;

        add_page_to_pdf(
            &doc,
            &mut page_index,
            &mut layer_index,
            page,
            width_mm,
            height_mm,
        )?;
    }

    // Save the PDF
    let file = File::create(output_path).context("Failed to create output file")?;
    let mut writer = BufWriter::new(file);
    doc.save(&mut writer)
        .context("Failed to save PDF document")?;

    eprintln!("Safe PDF created successfully at: {}", output_path);
    Ok(())
}

fn add_page_to_pdf(
    doc: &PdfDocumentReference,
    page_index: &mut PdfPageIndex,
    layer_index: &mut PdfLayerIndex,
    page: &PageData,
    width_mm: f32,
    height_mm: f32,
) -> Result<()> {
    // Convert pixel data to an image
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
        ImageBuffer::from_raw(page.width as u32, page.height as u32, page.pixels.clone())
            .context("Failed to create image from pixel data")?;

    // Convert to DynamicImage
    let dynamic_img = DynamicImage::ImageRgb8(img);

    // Create an image object for the PDF
    let image = Image::from_dynamic_image(&dynamic_img);

    // Add the image to the page
    let layer = doc.get_page(*page_index).get_layer(*layer_index);
    image.add_to_layer(
        layer.clone(),
        ImageTransform {
            translate_x: Some(Mm(0.0)),
            translate_y: Some(Mm(0.0)),
            scale_x: Some(width_mm / (page.width as f32)),
            scale_y: Some(height_mm / (page.height as f32)),
            ..Default::default()
        },
    );

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("Dangerzone Rust CLI");
    eprintln!("Using container runtime: podman");
    eprintln!("Input: {}", args.input);
    eprintln!("Output: {}", args.output);
    eprintln!();

    let pixels_data = convert_doc_to_pixels(&args.input)?;
    let pages = parse_pixel_data(&pixels_data)?;
    convert_pixels_to_pdf(&pages, &args.output)?;

    eprintln!();
    eprintln!("Conversion completed successfully!");
    eprintln!("Processed {} page(s)", pages.len());
    Ok(())
}
