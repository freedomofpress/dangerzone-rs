# dangerzone.rs

[![CI](https://github.com/freedomofpress/dangerzone-rs/workflows/CI/badge.svg)](https://github.com/freedomofpress/dangerzone-rs/actions)

> [!WARNING]
> This project is experimental and should not be used in production.
> For production use, please use the official [Dangerzone](https://dangerzone.rocks) implementation.

A minimal Rust implementation of [Dangerzone](https://dangerzone.rocks) that
converts potentially dangerous documents into safe PDFs.

## What does it do?

This tool takes untrusted documents (PDFs, Office files, images, etc.) and
converts them into safe PDFs by:

1. **Converting to pixels**: Documents are rendered to raw RGB pixel data in a
   sandboxed container
3. **Generating clean PDF**: A new PDF is created from scratch, embedding only
   the pixel data

This process removes any malicious code, macros, or exploits that may be hidden
in the original document.

## Why is this a good thing?

The main goal is to have both a library and a small binary (1.2MB) that runs on top of
podman to do conversions. Additionally, unlike other implementations, this this
doesn't rely on external PDF libraries like `muPDF`. Instead, it manually
constructs PDFs following the PDF 1.4 specification.

## Usage

### Command-line Interface

Basic conversion:
```bash
dangerzone-rs --input unsafe.pdf --output safe.pdf
```

With OCR:
```bash
dangerzone-rs --input unsafe.pdf --output safe.pdf --ocr
```

**Note on OCR**:

OCR uses the integrated Tesseract backend and writes the text layer directly
into the generated safe PDF.

### Python Library

Use dangerzone-rs as a Python library to programmatically convert documents.

#### Installation

As this is not published to PyPI, here is how to install it locally:

```bash
uv venv
source .venv/bin/activate
uv tool install maturin
maturin develop --features python
```

#### Basic Usage

Run the demos like this:

```bash
python demo/demo.py
```

#### Requirements

- **Podman**: The container runtime (required for document conversion)
- **Dangerzone container image**:
  ```bash
  podman pull ghcr.io/freedomofpress/dangerzone/v1
  ```

## Prerequisites (CLI)

- Rust (for building the binary from source)
- Podman
- Dangerzone container image:
  ```bash
  podman pull ghcr.io/freedomofpress/dangerzone/v1
  ```

## Installation

### CLI Binary

#### Download pre-built binaries

Download the latest release for your platform from the [Releases
page](https://github.com/almet/dangerzone-rs/releases).

Available platforms:

- Linux (x86_64, ARM64)
- macOS (Intel x86_64, Apple Silicon ARM64)
- Windows (x86_64)

#### Build from Source

**Prerequisites:**
For static linking the `kreuzberg-tesseract` crate you need to have:

- A C++ compiler (e.g., gcc, clang, MSVC on Windows)
- CMake 3.x or later
- Internet connection (for downloading Tesseract source code)

```bash
cargo build --release
./target/release/dangerzone-rs --input unsafe.pdf --output safe.pdf
```

#### Cross-compilation

You can build for most platforms from a Linux machine:

```bash
# Linux x86_64 (native)
cargo build --release --target x86_64-unknown-linux-gnu

# Linux ARM64 (requires cross: cargo install cross)
cross build --release --target aarch64-unknown-linux-gnu

# macOS (requires zig and cargo-zigbuild: cargo install cargo-zigbuild)
cargo zigbuild --release --target x86_64-apple-darwin
cargo zigbuild --release --target aarch64-apple-darwin

# Windows (requires cross: cargo install cross)
cross build --release --target x86_64-pc-windows-gnu
```

Note: The CI builds Windows using MSVC on `windows-latest` for better compatibility.
The GNU target above works for local development.

## How it works

The container converts documents to a binary stream:

- Page count (2 bytes, big-endian)
- For each page: width (2 bytes), height (2 bytes), RGB pixels (3 bytes per pixel)

The Rust code parses this stream and generates a minimal PDF that contains only
the pixel data as uncompressed RGB images. No external PDF library needed.
