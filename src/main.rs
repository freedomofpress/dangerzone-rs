//! The `dangerzone-rs` command-line tool.

use std::path::PathBuf;

use anyhow::Result;
use clap::builder::{PathBufValueParser, TypedValueParser};
use clap::Parser;
use dangerzone_rs::{convert_document, Untrusted};

/// A simple Dangerzone CLI implementation in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input document path
    #[arg(short, long, value_parser = PathBufValueParser::new().map(Untrusted::new))]
    input: Untrusted<PathBuf>,

    /// Output PDF path
    #[arg(short, long, value_parser = PathBufValueParser::new().map(Untrusted::new))]
    output: Untrusted<PathBuf>,

    /// Enable OCR to add text layer to PDF
    #[arg(long)]
    ocr: bool,
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

    convert_document(args.input, args.output, args.ocr)?;

    eprintln!();
    eprintln!("Conversion completed successfully!");
    Ok(())
}
