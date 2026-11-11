# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/freedomofpress/dangerzone-rs/compare/v0.1.0...HEAD)

### Added

- Embed the English language data for OCR in the binary, so that OCR works
  without installing Tesseract. A Tesseract installation with English language
  data, or `TESSDATA_PREFIX`, still takes priority.
- License the project under the AGPL-3.0, like Dangerzone.

### Removed

- **Breaking change**: Remove the Python bindings.

### Development changes

- Build Tesseract with xberg-tesseract, which replaces kreuzberg-tesseract.
- Lints are configured in `Cargo.toml`, and fail local builds as well as CI.
