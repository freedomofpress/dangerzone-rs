use anyhow::Result;
use clap::Parser;
use dangerzone_rs::convert_document;
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
    }
    eprintln!();

    convert_document(args.input, args.output, args.ocr)?;

    eprintln!();
    eprintln!("Conversion completed successfully!");
    Ok(())
}
