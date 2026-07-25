//! OCR backend powered by `kreuzberg-tesseract`.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use kreuzberg_tesseract::{Pix, ResultIterator, TesseractAPI};
use rayon::{prelude::*, ThreadPoolBuilder};

use crate::{PageData, DPI};

use super::{OcrBackend, OcrPage, OcrVBox, OcrWord};

/// OCR backend powered by `kreuzberg-tesseract`.
pub(crate) struct KreuzbergTesseractOcr;

/// Since the `KreuzbergTesseractOcr` backend will be always called
/// in parallel, we need a seperate type representing the worker.
/// This worker will be initialized in the Rayon workers, and will
/// contain the logic to do OCR work for a page.
struct KreuzbergTesseractOcrWorker {
    api: TesseractAPI,
}

impl KreuzbergTesseractOcrWorker {
    /// Create new instance of OCR worker. This worker will
    /// contain the logic to init the Tesseract API instance + doing
    /// OCR for a page. Since each Rayon worker will have one
    /// OCR-worker this is the logical structure.
    fn new() -> Result<Self> {
        let api = TesseractAPI::new().context("Failed to create Tesseract API")?;
        let tessdata_dir = Self::tessdata_dir().context("Failed to find Tesseract tessdata")?;

        // Seed Tesseract with trained language data.
        // TODO: Currently we only support English. Support other languages too.
        // See https://github.com/freedomofpress/dangerzone-rs/issues/14
        api.init(&tessdata_dir, "eng")
            .context("Failed to initialize Tesseract API")?;

        Ok(Self { api })
    }

    /// Resolve the tessdata directory used to initialize Tesseract
    ///
    /// `TESSDATA_PREFIX` has priority when set. Otherwise we use the tessdata
    /// bundled by `kreuzberg-tesseract`.
    fn tessdata_dir() -> Option<PathBuf> {
        // Honor the standard Tesseract override first. Callers may point this
        // either at the tessdata directory itself or at its parent.
        if let Ok(path) = std::env::var("TESSDATA_PREFIX") {
            return Some(Self::as_tessdata_dir(PathBuf::from(path)));
        }

        let mut candidates = Vec::new();

        // `kreuzberg-tesseract`'s build script downloads bundled English
        // traineddata under {TESSDATA_PREFIX_BUNDLED}/tessdata and exports the
        // prefix at compile time.
        if let Some(path) = option_env!("TESSDATA_PREFIX_BUNDLED") {
            candidates.push(Self::as_tessdata_dir(PathBuf::from(path)));
        }

        #[cfg(target_os = "linux")]
        {
            // Common package locations for Tesseract 5 and older distro
            // layouts. These are used when tessdata was installed system-wide.
            candidates.push(PathBuf::from("/usr/share/tesseract-ocr/5/tessdata"));
            candidates.push(PathBuf::from("/usr/share/tesseract-ocr/tessdata"));

            // Cache directory used by `kreuzberg-tesseract`.
            if let Some(home) = std::env::var_os("HOME") {
                candidates.push(PathBuf::from(home).join(".kreuzberg-tesseract/tessdata"));
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                candidates.push(
                    PathBuf::from(home)
                        .join("Library/Application Support/kreuzberg-tesseract/tessdata"),
                );
            }

            // Homebrew's default prefixes on Apple Silicon and Intel Macs.
            candidates.push(PathBuf::from("/opt/homebrew/share/tessdata"));
            candidates.push(PathBuf::from("/usr/local/share/tessdata"));
        }

        #[cfg(target_os = "windows")]
        {
            // Default cache used by kreuzberg-tesseract's Windows build.
            candidates.push(PathBuf::from(r"C:\tess\tessdata"));

            if let Some(app_data) = std::env::var_os("APPDATA") {
                candidates.push(
                    PathBuf::from(app_data)
                        .join("kreuzberg-tesseract")
                        .join("tessdata"),
                );
            }

            // Standard locations used by Windows Tesseract installers.
            for program_files in ["ProgramFiles", "ProgramFiles(x86)"] {
                if let Some(path) = std::env::var_os(program_files) {
                    candidates.push(PathBuf::from(path).join("Tesseract-OCR/tessdata"));
                }
            }
        }

        candidates.into_iter().find(|path| path.exists())
    }

    // TESSDATA_PREFIX can either mean the tessdata directory itself or the parent prefix. This is
    // also used interchangebly in the documentation. Normalize both.
    fn as_tessdata_dir(path: PathBuf) -> PathBuf {
        if path.ends_with("tessdata") {
            path
        } else {
            path.join("tessdata")
        }
    }

    fn ocr_page(&self, pixels: &[u8], width: u16, height: u16) -> Result<OcrPage> {
        // Pass container's bytes directly using Leptonica's Pix wrapper
        // exposed by `kreuzberg-tesseract`.
        let rgb_pix = Pix::from_raw_rgb(pixels, width.into(), height.into())
            .context("Failed to create Leptonica Pix from RGB pixels")?;

        // Convert the container-rendered RGB page to grayscale before OCR.
        let mut pix = rgb_pix
            .to_grayscale()
            .context("Failed to convert OCR image to grayscale")?;

        let dpi = DPI as i32;

        // Store the container-rendered resolution on the Pix as image metadata
        // so Tesseract can interpret text size correctly.
        pix.set_resolution(dpi, dpi)
            .context("Failed to set OCR image resolution")?;

        // Give Tesseract the Leptonica image. `set_image_2` borrows the Pix
        // pointer; keep `pix` alive for the rest of this method.
        self.api
            .set_image_2(pix.as_ptr())
            .context("Failed to pass image to Tesseract")?;

        self.api
            .recognize()
            .context("Failed to run Tesseract recognition")?;

        let iterator = self
            .api
            .get_iterator()
            .context("Failed to get Tesseract result iterator")?;

        Ok(OcrPage::new(extract_ocr_words(&iterator)?))
    }
}

impl KreuzbergTesseractOcr {
    /// Create instance of `KreuzbergTesseractOcr`.
    /// This type only contains methods to call logic for
    /// parallel OCR.
    pub(crate) fn new() -> Self {
        Self
    }

    /// Amount of max workers.
    /// The amount of workers is half the amount of available CPU cores to avoid overloading the
    /// CPU.
    fn max_workers() -> usize {
        std::thread::available_parallelism()
            .map(|cpus| std::cmp::max(1, cpus.get() / 2))
            .unwrap_or(1)
    }

    /// Handle OCR for all pages in parallel.
    /// This method creates a pool of Rayon workers, each Rayon-worker will initialize it's own
    /// instance of a `KreuzbergTesseractWorker` containing a Tesseract object.
    fn ocr_pages_parallel(&self, pages: &[PageData]) -> Result<Vec<OcrPage>> {
        // Create pool of Rayon workers.
        let pool = ThreadPoolBuilder::new()
            .num_threads(Self::max_workers())
            .build()
            .context("Failed to create pool of Rayon workers for parallel OCR.")?;

        // Set previous initiated pool to run closure.
        pool.install(|| {
            pages
                .par_iter() // Convert iter into Rayon parallel iterator.
                .map_init(
                    // The `init` argument for `map_init`.
                    // Each worker wil init its own instance of `KreuzbergTesseractWorker`
                    // responsible for performing the OCR on the allocated pages.
                    KreuzbergTesseractOcrWorker::new,
                    // `ocr_worker` is the result of our previous `map_init` call.
                    // `page` is one item from the `pages.par_item` allocted to current worker.
                    |ocr_worker, page| -> Result<OcrPage> {
                        // Get OCR-worker as reference so we do not move it out
                        // of the local Rayon-worker.
                        let worker = ocr_worker.as_ref().map_err(|err| {
                            anyhow!("Failed to init KreuzbergTesseractWorker: {err}")
                        })?;

                        worker
                            .ocr_page(&page.pixels, page.width, page.height)
                            .with_context(|| "Failed to run KreuzbergTesseractOCR.".to_string())
                    },
                )
                .collect::<Result<Vec<OcrPage>>>()
        })
    }
}

impl OcrBackend for KreuzbergTesseractOcr {
    fn ocr_pages(&self, pages: &[PageData]) -> Result<Vec<OcrPage>> {
        self.ocr_pages_parallel(pages)
    }
}

/// Extract OCR words and their properties.
///
/// Uses `kreuzberg-tesseract`'s high-level iterator helper instead of local
/// low-level Tesseract bindings.
fn extract_ocr_words(iterator: &ResultIterator) -> Result<Vec<OcrWord>> {
    let words = iterator
        .extract_all_words()
        .context("Failed to extract OCR words from Tesseract result iterator")?;

    Ok(words
        .into_iter()
        .filter_map(|word| {
            let text = word.text.trim().to_string();
            if text.is_empty() {
                return None;
            }

            let w = word.right - word.left;
            let h = word.bottom - word.top;
            if w <= 0 || h <= 0 {
                return None;
            }

            Some(OcrWord {
                text,
                vbox: OcrVBox {
                    x: word.left,
                    y: word.top,
                    w,
                    h,
                },
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::KreuzbergTesseractOcr;

    #[test]
    fn initializes_with_tesseract_data() {
        KreuzbergTesseractOcr::new()
            .expect("Tesseract data should be available on every supported platform");
    }
}
