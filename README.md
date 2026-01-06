# dangerzone.rs

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

Or using cargo run:
```bash
cargo run -- --input unsafe.pdf --output safe.pdf
```

## Supported Document Formats

The implementation supports all formats supported by the Dangerzone container:
- PDF documents (.pdf)
- Microsoft Office documents (.docx, .xlsx, .pptx, .doc, .xls, .ppt)
- OpenDocument formats (.odt, .ods, .odp, .odg)
- Image files (.jpg, .png, .gif, .bmp, .tiff, .svg)
- E-books (.epub)
- And more...

## Testing

To test the implementation, you'll need:
1. A document to convert (e.g., `test.pdf`)
2. The Dangerzone container image pulled

Example:
```bash
# Pull the container image
podman pull ghcr.io/freedomofpress/dangerzone/v1

# Convert a document
cargo run -- --input test.pdf --output safe.pdf
```

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