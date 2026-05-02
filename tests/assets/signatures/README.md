# Signature Test Assets

This folder contains signature test assets used for testing signature verification functionality in dangerzone-rs. These assets were imported from the [freedomofpress/dangerzone](https://github.com/freedomofpress/dangerzone) repository.

## Directory Structure

```
signatures/
├── valid/     - Properly formatted signatures generated with the test key
├── invalid/   - Improperly formatted signatures (e.g., plain text instead of base64)
└── tampered/  - Correctly formatted but tampered signatures
```

## Test Categories

### Valid Signatures (`valid/`)
Contains signatures which should be considered valid and were generated with the key available at `tests/assets/test.pub.key`. These signatures have:
- Correct format (base64-encoded)
- Valid structure
- Proper cryptographic signatures
- Valid log indices

### Invalid Signatures (`invalid/`)
Contains signatures which should be considered invalid because their format doesn't match the expected structure. Examples include:
- Plain text instead of base64-encoded text
- Malformed JSON
- Missing required fields

### Tampered Signatures (`tampered/`)
Contains signatures that have been tampered with. The goal is to have signatures that look valid but actually aren't. Their format is correct but the contents don't match the signatures.

## Usage

These test assets are used by the Rust tests in `tests/test_signatures.rs` to verify that:
1. Valid signatures are correctly loaded and parsed
2. Invalid signatures are rejected
3. Tampered signatures are detected
4. Signature metadata (log index, manifest digest) is correctly extracted

## Original Source

These assets were imported from:
- Repository: https://github.com/freedomofpress/dangerzone
- Path: `tests/assets/signatures/`
- Python tests: `tests/test_signatures.py`

The Rust tests in this repository (`tests/test_signatures.rs`) are adapted from the Python tests to work with dangerzone-rs.
