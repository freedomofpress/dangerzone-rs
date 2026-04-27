use anyhow::Result;
use clap::{Parser, ValueEnum};
use dangerzone_rs::{convert_document_with_ocr_backend, OcrBackend};
use util::replace_control_chars;

mod util;

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

    /// OCR backend to use when --ocr is enabled
    #[arg(long, value_enum, default_value_t = CliOcrBackend::Kreuzberg)]
    ocr_backend: CliOcrBackend,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliOcrBackend {
    Kreuzberg,
    Ocrmypdf,
}

impl From<CliOcrBackend> for OcrBackend {
    fn from(value: CliOcrBackend) -> Self {
        match value {
            CliOcrBackend::Kreuzberg => OcrBackend::Kreuzberg,
            CliOcrBackend::Ocrmypdf => OcrBackend::Ocrmypdf,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("Dangerzone Rust CLI");
    eprintln!("Using container runtime: podman");
    eprintln!(
        "Input: {input_sanitized}",
        input_sanitized = replace_control_chars(&args.input, false)
    );
    eprintln!(
        "Output: {output_sanitized}",
        output_sanitized = replace_control_chars(&args.output, false)
    );
    if args.ocr {
        eprintln!("OCR: enabled");
        eprintln!("OCR backend: {:?}", args.ocr_backend);
    }
    eprintln!();

    convert_document_with_ocr_backend(args.input, args.output, args.ocr, args.ocr_backend.into())?;

    eprintln!();
    eprintln!("Conversion completed successfully!");
    Ok(())
}
