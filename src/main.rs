use anyhow::Result;
use clap::{Parser, Subcommand};
use dangerzone_rs::{convert_document, cosign, debugprint, set_debug, IMAGE_NAME, TRUSTED_PUBKEY};
use util::replace_control_chars;

mod util;

/// Dangerzone – convert untrusted documents into safe PDFs
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Print verbose progress information
    #[arg(long, global = true)]
    debug: bool,

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
    let cli = Cli::parse();
    set_debug(cli.debug);

    debugprint!("Dangerzone Rust CLI");
    debugprint!("Using container runtime: podman");
    debugprint!();

    match cli.command {
        Commands::Convert { input, output, ocr } => {
            debugprint!(
                "Input:  {input_sanitized}",
                input_sanitized = replace_control_chars(&input, false)
            );
            debugprint!(
                "Output: {output_sanitized}",
                output_sanitized = replace_control_chars(&output, false)
            );
            if ocr {
                debugprint!("OCR: enabled");
            }
            debugprint!();

            convert_document(input, output, ocr)?;

            debugprint!();
            debugprint!("Conversion completed successfully!");
        }

        Commands::Upgrade => {
            cosign::upgrade_image(IMAGE_NAME, TRUSTED_PUBKEY)?;
            debugprint!();
            debugprint!("Upgrade completed successfully!");
        }
    }

    Ok(())
}
