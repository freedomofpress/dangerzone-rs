use anyhow::Result;
use clap::{Parser, Subcommand};
use dangerzone_rs::{convert_document, cosign, IMAGE_NAME, TRUSTED_PUBKEY};
use util::replace_control_chars;

mod util;

/// Dangerzone – convert untrusted documents into safe PDFs
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Convert a document to a safe PDF
    Convert {
        /// Input document path
        #[arg(short, long)]
        input: String,

        /// Output PDF path
        #[arg(short, long)]
        output: String,

        /// Enable OCR to add a text layer to the PDF
        #[arg(long, default_value = "false")]
        ocr: bool,
    },

    /// Pull the container image, download, verify, and store its signatures.
    ///
    /// Run this once before using `convert` for the first time, and again
    /// whenever a new image version is released.
    Upgrade,
}

fn main() -> Result<()> {
    eprintln!("Dangerzone Rust CLI");
    eprintln!("Using container runtime: podman");
    eprintln!();

    let cli = Cli::parse();

    match cli.command {
        Commands::Convert { input, output, ocr } => {
            eprintln!(
                "Input:  {input_sanitized}",
                input_sanitized = replace_control_chars(&input, false)
            );
            eprintln!(
                "Output: {output_sanitized}",
                output_sanitized = replace_control_chars(&output, false)
            );
            if ocr {
                eprintln!("OCR: enabled");
            }
            eprintln!();

            convert_document(input, output, ocr)?;

            eprintln!();
            eprintln!("Conversion completed successfully!");
        }

        Commands::Upgrade => {
            cosign::upgrade_image(IMAGE_NAME, TRUSTED_PUBKEY)?;
            eprintln!();
            eprintln!("Upgrade completed successfully!");
        }
    }

    Ok(())
}
