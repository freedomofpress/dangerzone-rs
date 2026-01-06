use image::GenericImageView;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

const INPUTS_DIR: &str = "test_docs/inputs";
const REFERENCE_DIR: &str = "test_docs/reference";

/// Represents a test case with input file and expected reference output
struct TestCase {
    input_path: PathBuf,
    reference_path: Option<PathBuf>,
    should_succeed: bool,
}

fn discover_test_files() -> Vec<TestCase> {
    let inputs_dir = Path::new(INPUTS_DIR);
    let reference_dir = Path::new(REFERENCE_DIR);

    let mut test_cases = Vec::new();

    // Walk through all files in inputs directory
    for entry in WalkDir::new(inputs_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Skip directories
        if path.is_dir() {
            continue;
        }

        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Determine if this test should succeed or fail based on filename
        let should_succeed = !file_name.starts_with("sample_bad");

        // Find corresponding reference PDF if test should succeed
        let reference_path = if should_succeed {
            let pdf_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| format!("{}.pdf", s))
                .unwrap_or_default();

            let ref_path = reference_dir.join(pdf_name);
            if ref_path.exists() {
                Some(ref_path)
            } else {
                None
            }
        } else {
            None
        };

        test_cases.push(TestCase {
            input_path: path.to_path_buf(),
            reference_path,
            should_succeed,
        });
    }

    test_cases
}

fn run_conversion(input: &Path, output: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let status = Command::new("cargo")
        .args(["run", "--", "--input"])
        .arg(input)
        .arg("--output")
        .arg(output)
        .status()?;

    Ok(status.success())
}

fn compare_pdfs_pixel_by_pixel(
    generated: &Path,
    reference: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Use pdftoppm to convert PDFs to images for comparison
    let gen_png = generated.with_extension("png");
    let ref_png = reference.with_extension("png");

    // Convert generated PDF to PNG
    let gen_status = Command::new("pdftoppm")
        .args([
            "-png",
            "-singlefile",
            "-r",
            "150", // 150 DPI to match our rendering
        ])
        .arg(generated)
        .arg(generated.with_extension(""))
        .status();

    // Convert reference PDF to PNG
    let ref_status = Command::new("pdftoppm")
        .args(["-png", "-singlefile", "-r", "150"])
        .arg(reference)
        .arg(reference.with_extension(""))
        .status();

    if gen_status.is_err() || ref_status.is_err() {
        eprintln!("Warning: pdftoppm not available, falling back to file size comparison");
        return compare_pdf_sizes(generated, reference);
    }

    // Load both images
    let gen_img = image::open(&gen_png)?;
    let ref_img = image::open(&ref_png)?;

    // Clean up temporary PNGs
    let _ = fs::remove_file(&gen_png);
    let _ = fs::remove_file(&ref_png);

    // Compare dimensions
    if gen_img.dimensions() != ref_img.dimensions() {
        eprintln!(
            "Image dimensions differ: generated={:?}, reference={:?}",
            gen_img.dimensions(),
            ref_img.dimensions()
        );
        return Ok(false);
    }

    // Convert to RGB for comparison
    let gen_rgb = gen_img.to_rgb8();
    let ref_rgb = ref_img.to_rgb8();

    let (width, height) = gen_rgb.dimensions();
    let total_pixels = (width * height) as usize;
    let mut different_pixels = 0;

    // Compare pixel by pixel
    for y in 0..height {
        for x in 0..width {
            let gen_pixel = gen_rgb.get_pixel(x, y);
            let ref_pixel = ref_rgb.get_pixel(x, y);

            if gen_pixel != ref_pixel {
                different_pixels += 1;
            }
        }
    }

    let similarity = 1.0 - (different_pixels as f64 / total_pixels as f64);

    // Allow up to 1% pixel difference (due to PDF rendering variations)
    if similarity < 0.99 {
        eprintln!(
            "Images differ by {:.2}% ({} out of {} pixels)",
            (1.0 - similarity) * 100.0,
            different_pixels,
            total_pixels
        );
        return Ok(false);
    }

    Ok(true)
}

fn compare_pdf_sizes(
    generated: &Path,
    reference: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let gen_metadata = fs::metadata(generated)?;
    let ref_metadata = fs::metadata(reference)?;

    let gen_size = gen_metadata.len();
    let ref_size = ref_metadata.len();

    let size_diff_percent = ((gen_size as f64 - ref_size as f64) / ref_size as f64).abs() * 100.0;

    // Allow 50% size difference
    if size_diff_percent > 50.0 {
        eprintln!(
            "PDF size differs too much: generated={}, reference={}, diff={:.1}%",
            gen_size, ref_size, size_diff_percent
        );
        return Ok(false);
    }

    Ok(true)
}

#[test]
#[ignore] // Requires podman and dangerzone image
fn test_all_documents() -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = discover_test_files();

    if test_cases.is_empty() {
        return Err(format!("No test files found in {} directory", INPUTS_DIR).into());
    }

    let total = test_cases.len();
    let failed_tests = Arc::new(Mutex::new(Vec::new()));
    let passed = Arc::new(Mutex::new(0));

    // Use parallel iterator for faster test execution
    test_cases.par_iter().for_each(|test_case| {
        let input_name = test_case
            .input_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        println!("\nTesting: {}", input_name);

        let output_path = PathBuf::from(format!("/tmp/test-output-{}.pdf", input_name));

        // Run conversion
        let conversion_succeeded = match run_conversion(&test_case.input_path, &output_path) {
            Ok(success) => success,
            Err(e) => {
                failed_tests
                    .lock()
                    .unwrap()
                    .push(format!("{}: Conversion error: {}", input_name, e));
                return;
            }
        };

        // Check if result matches expectation
        if test_case.should_succeed {
            if !conversion_succeeded {
                failed_tests.lock().unwrap().push(format!(
                    "{}: Expected success but conversion failed",
                    input_name
                ));
                return;
            }

            if !output_path.exists() {
                failed_tests
                    .lock()
                    .unwrap()
                    .push(format!("{}: Output PDF not created", input_name));
                return;
            }

            // Compare with reference if available
            if let Some(ref_path) = &test_case.reference_path {
                match compare_pdfs_pixel_by_pixel(&output_path, ref_path) {
                    Ok(true) => {
                        println!("✓ {}: Pixel comparison passed", input_name);
                        *passed.lock().unwrap() += 1;
                    }
                    Ok(false) => {
                        failed_tests
                            .lock()
                            .unwrap()
                            .push(format!("{}: PDF comparison failed", input_name));
                    }
                    Err(e) => {
                        eprintln!("Warning: Could not compare PDFs: {}", e);
                        // Fall back to size comparison
                        match compare_pdf_sizes(&output_path, ref_path) {
                            Ok(true) => {
                                println!("✓ {}: Size comparison passed", input_name);
                                *passed.lock().unwrap() += 1;
                            }
                            Ok(false) => {
                                failed_tests
                                    .lock()
                                    .unwrap()
                                    .push(format!("{}: Size comparison failed", input_name));
                            }
                            Err(e) => {
                                failed_tests
                                    .lock()
                                    .unwrap()
                                    .push(format!("{}: Comparison error: {}", input_name, e));
                            }
                        }
                    }
                }
            } else {
                println!("✓ {}: Conversion succeeded (no reference)", input_name);
                *passed.lock().unwrap() += 1;
            }

            // Clean up
            let _ = fs::remove_file(&output_path);
        } else {
            // Test should fail
            if conversion_succeeded {
                failed_tests.lock().unwrap().push(format!(
                    "{}: Expected failure but conversion succeeded",
                    input_name
                ));
            } else {
                println!("✓ {}: Failed as expected", input_name);
                *passed.lock().unwrap() += 1;
            }
        }
    });

    let passed_count = *passed.lock().unwrap();
    let failed = failed_tests.lock().unwrap();

    println!("\n========================================");
    println!("Test Results: {}/{} passed", passed_count, total);
    println!("========================================");

    if !failed.is_empty() {
        println!("\nFailed tests:");
        for failure in failed.iter() {
            println!("  ✗ {}", failure);
        }
        return Err(format!("{} test(s) failed", failed.len()).into());
    }

    Ok(())
}

#[test]
#[ignore]
fn test_single_docx() -> Result<(), Box<dyn std::error::Error>> {
    let input = Path::new(INPUTS_DIR).join("sample-docx.docx");
    let output = Path::new("/tmp/test-docx-single.pdf");
    let reference = Path::new(REFERENCE_DIR).join("sample-docx.pdf");

    if !input.exists() {
        return Err("Test file not found".into());
    }

    let success = run_conversion(&input, output)?;
    assert!(success, "Conversion failed");
    assert!(output.exists(), "Output not created");

    if reference.exists() {
        let comparison = compare_pdfs_pixel_by_pixel(output, &reference)?;
        assert!(comparison, "PDF comparison failed");
    }

    fs::remove_file(output)?;
    Ok(())
}

/// Regenerate all reference PDFs from input files
/// Run with: cargo test --test integration_test regenerate_all_references -- --ignored --nocapture
#[test]
#[ignore]
fn regenerate_all_references() -> Result<(), Box<dyn std::error::Error>> {
    let inputs_dir = Path::new(INPUTS_DIR);
    let reference_dir = Path::new(REFERENCE_DIR);

    // Ensure reference directory exists
    fs::create_dir_all(reference_dir)?;

    println!("Regenerating all reference PDFs...\n");

    let mut regenerated = 0;
    let mut failed = 0;

    for entry in WalkDir::new(inputs_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Skip directories
        if path.is_dir() {
            continue;
        }

        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Skip files expected to fail
        if file_name.starts_with("sample_bad") {
            println!("Skipping (expected to fail): {}", file_name);
            continue;
        }

        let pdf_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| format!("{}.pdf", s))
            .unwrap_or_default();

        let ref_path = reference_dir.join(&pdf_name);

        println!("Generating reference for: {}", file_name);

        let success = run_conversion(path, &ref_path)?;

        if success && ref_path.exists() {
            println!("✓ Created: {}", pdf_name);
            regenerated += 1;
        } else {
            println!("✗ Failed: {}", file_name);
            failed += 1;
        }
    }

    println!("\n========================================");
    println!("Regeneration complete:");
    println!("  Created: {}", regenerated);
    println!("  Failed: {}", failed);
    println!("========================================");

    if failed > 0 {
        return Err(format!("{} file(s) failed to regenerate", failed).into());
    }

    Ok(())
}
