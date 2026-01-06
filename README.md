# dangerzone.rs

[![CI](https://github.com/almet/dangerzone.rs/workflows/CI/badge.svg)](https://github.com/almet/dangerzone.rs/actions)

A command-line implementation of Dangerzone in Rust.

## Overview

This is a simple Rust implementation of Dangerzone that converts potentially dangerous documents (PDF, Office documents, etc.) into safe PDFs by rendering them to pixels and reconstructing a clean PDF.

## Features

- Uses the official Dangerzone Docker images from `ghcr.io/freedomofpress/dangerzone/v1`
- Uses podman for container runtime
- Streams documents through the conversion process
- Two-phase conversion: document → pixels → safe PDF
- Parses the binary pixel stream protocol
- Reconstructs PDF from pixel data using Rust PDF libraries

## Prerequisites

- Rust (for building)
- Podman installed and running
- The Dangerzone container image pulled:
  ```bash
  podman pull ghcr.io/freedomofpress/dangerzone/v1
  ```

## Building

```bash
cargo build --release
```

The binary will be available at `target/release/dangerzone-rs`.

## Usage

Basic usage:
```bash
dangerzone-rs --input unsafe.pdf --output safe.pdf
```

With OCR enabled:
```bash
dangerzone-rs --input unsafe.pdf --output safe.pdf --ocr
```

Or using cargo run:
```bash
cargo run -- --input unsafe.pdf --output safe.pdf
```

## OCR Support

The `--ocr` flag enables OCR (Optical Character Recognition) to add a searchable text layer to the output PDF. This requires `ocrmypdf` to be installed:

```bash
pip install ocrmypdf
```

If `ocrmypdf` is not available, the conversion will continue without OCR and produce a PDF without text layers.

## Supported Document Formats

The implementation supports all formats supported by the Dangerzone container:
- PDF documents (.pdf)
- Microsoft Office documents (.docx, .xlsx, .pptx, .doc, .xls, .ppt)
- OpenDocument formats (.odt, .ods, .odp, .odg)
- Image files (.jpg, .png, .gif, .bmp, .tiff, .svg)
- E-books (.epub)
- And more...

## Testing

### Local Testing

Unit tests:
```bash
cargo test
```

Integration tests (requires podman, dangerzone image, and optionally pdftoppm):
```bash
# Pull the container image first
podman pull ghcr.io/freedomofpress/dangerzone/v1

# Install pdftoppm for pixel-by-pixel comparison (optional, falls back to size comparison)
# On Ubuntu/Debian: sudo apt-get install poppler-utils
# On macOS: brew install poppler

# Run all integration tests in parallel (tests all files in test_docs/inputs/ automatically)
cargo test --test integration_test -- --ignored --test-threads=4

# Run single test
cargo test --test integration_test test_single_docx -- --ignored

# Regenerate all reference PDFs (useful after code changes)
cargo test --test integration_test regenerate_all_references -- --ignored --nocapture
```

### Continuous Integration

The project uses GitHub Actions for CI/CD with the following workflows:

- **Unit Tests**: Run on Ubuntu, macOS, and Windows with stable Rust
- **Integration Tests**: Run on Ubuntu and macOS with podman
- **Linting**: Format checking and clippy on all platforms

Tests are parallelized using rayon for faster execution. The integration test suite typically completes in under 5 minutes on CI with 4 parallel threads.

### Test Organization

Test files are organized in `test_docs/`:
- `test_docs/inputs/`: Input documents for testing
- `test_docs/reference/`: Reference PDFs for comparison

The integration test suite:
- Automatically discovers all files in `test_docs/inputs/`
- Determines expected behavior based on filename (`sample_bad_*` files expected to fail)
- Compares converted PDFs with references using pixel-by-pixel comparison (requires `pdftoppm`)
- Falls back to file size comparison if `pdftoppm` is not available
- Provides detailed pass/fail reporting

### Regenerating References

If you've made improvements to the conversion and want to update the reference PDFs:

```bash
cargo test --test integration_test regenerate_all_references -- --ignored --nocapture
```

This will convert all input files (except `sample_bad_*`) and save them to `test_docs/reference/`.

## How it works

1. **Document to Pixels**: The input document is streamed to stdin of a sandboxed podman container that converts it to pixel data
2. **Parse Pixel Stream**: The binary output stream is parsed according to the Dangerzone protocol:
   - Page count (2 bytes, big-endian)
   - For each page: width (2 bytes), height (2 bytes), RGB pixel data
3. **Pixels to PDF**: The pixel data is converted to a safe PDF using Rust PDF libraries

All conversions happen with strict security settings following the Dangerzone security model.

## Security Features

The implementation uses the same security flags as the official Dangerzone:
- `--security-opt no-new-privileges`: Prevents privilege escalation
- `--cap-drop all --cap-add SYS_CHROOT`: Minimal capabilities
- `--network=none`: No network access
- `-u dangerzone`: Run as unprivileged user
- `--rm`: Automatically remove containers after use
- `--log-driver none`: Don't log container output

## Implementation Details

This is a minimal implementation that demonstrates the core Dangerzone workflow:
- Uses the container for the untrusted document-to-pixels conversion
- Implements the binary I/O protocol for receiving pixel data
- Converts pixels back to PDF using the `printpdf` crate

## References

- [Dangerzone Project](https://github.com/freedomofpress/dangerzone)
- [Container Security Flags](https://github.com/freedomofpress/dangerzone/blob/main/dangerzone/isolation_provider/container.py)
- [Binary Protocol](https://github.com/freedomofpress/dangerzone/blob/main/dangerzone/conversion/common.py)