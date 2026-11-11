//! OCR backend powered by `xberg-tesseract`.

use std::path::PathBuf;

use rayon::{prelude::*, ThreadPoolBuilder};
use xberg_tesseract::{Pix, ResultIterator, TesseractAPI, TesseractError};

use crate::{OcrError, PageData, DPI};

use super::{OcrBackend, OcrPage, OcrVBox, OcrWord};

/// Tesseract's `OEM_DEFAULT` engine mode, which `TesseractAPI::init()` uses
/// as well. `xberg-tesseract` doesn't export it.
const OEM_DEFAULT: i32 = 3;

/// OCR backend powered by `xberg-tesseract`.
pub(crate) struct XbergTesseractOcr;

/// Since the `XbergTesseractOcr` backend will be always called
/// in parallel, we need a seperate type representing the worker.
/// This worker will be initialized in the Rayon workers, and will
/// contain the logic to do OCR work for a page.
struct XbergTesseractOcrWorker {
    api: TesseractAPI,
}

impl XbergTesseractOcrWorker {
    /// Create new instance of OCR worker. This worker will
    /// contain the logic to init the Tesseract API instance + doing
    /// OCR for a page. Since each Rayon worker will have one
    /// OCR-worker this is the logical structure.
    fn new() -> Result<Self, OcrError> {
        let api = TesseractAPI::new().map_err(tesseract_error("create the Tesseract API"))?;

        // Seed Tesseract with trained language data.
        // TODO: Currently we only support English. Support other languages too.
        // See https://github.com/freedomofpress/dangerzone-rs/issues/14
        match Self::tessdata_dir() {
            Some(tessdata_dir) => api.init(&tessdata_dir, "eng"),
            None => Self::init_with_bundled_tessdata(&api),
        }
        .map_err(tesseract_error("initialize the Tesseract API"))?;

        Ok(Self { api })
    }

    /// Resolve the tessdata directory used to initialize Tesseract
    ///
    /// `TESSDATA_PREFIX` has priority when set, followed by the places where
    /// Tesseract is usually installed. Only directories with English language
    /// data count, so that an empty or partial install doesn't shadow the
    /// language data embedded in the binary.
    fn tessdata_dir() -> Option<PathBuf> {
        let mut candidates = Vec::new();

        // Honor the standard Tesseract override first. Callers may point this
        // either at the tessdata directory itself or at its parent.
        if let Some(path) = std::env::var_os("TESSDATA_PREFIX") {
            candidates.push(Self::as_tessdata_dir(PathBuf::from(path)));
        }

        #[cfg(target_os = "linux")]
        {
            // Common package locations for Tesseract 5 and older distro
            // layouts. These are used when tessdata was installed system-wide.
            candidates.push(PathBuf::from("/usr/share/tesseract-ocr/5/tessdata"));
            candidates.push(PathBuf::from("/usr/share/tesseract-ocr/tessdata"));
        }

        #[cfg(target_os = "macos")]
        {
            // Homebrew's default prefixes on Apple Silicon and Intel Macs.
            candidates.push(PathBuf::from("/opt/homebrew/share/tessdata"));
            candidates.push(PathBuf::from("/usr/local/share/tessdata"));
        }

        #[cfg(target_os = "windows")]
        {
            // Standard locations used by Windows Tesseract installers.
            for program_files in ["ProgramFiles", "ProgramFiles(x86)"] {
                if let Some(path) = std::env::var_os(program_files) {
                    candidates.push(PathBuf::from(path).join("Tesseract-OCR/tessdata"));
                }
            }
        }

        candidates
            .into_iter()
            .find(|path| path.join("eng.traineddata").is_file())
    }

    /// Initialize Tesseract with the English language data that the build
    /// embeds in the binary, so that OCR works without installing Tesseract.
    fn init_with_bundled_tessdata(api: &TesseractAPI) -> xberg_tesseract::Result<()> {
        let data = xberg_tesseract::bundled_eng_traineddata().ok_or(TesseractError::InitError)?;
        let size = i32::try_from(data.len()).map_err(|_| TesseractError::InitError)?;
        api.init_5(data, size, "eng", OEM_DEFAULT, &[])
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

    fn ocr_page(&self, pixels: &[u8], width: u16, height: u16) -> Result<OcrPage, OcrError> {
        // Pass container's bytes directly using Leptonica's Pix wrapper
        // exposed by `xberg-tesseract`.
        let rgb_pix = Pix::from_raw_rgb(pixels, width.into(), height.into())
            .map_err(tesseract_error("create a Leptonica Pix from RGB pixels"))?;

        // Convert the container-rendered RGB page to grayscale before OCR.
        let mut pix = rgb_pix
            .to_grayscale()
            .map_err(tesseract_error("convert the OCR image to grayscale"))?;

        let dpi = DPI as i32;

        // Store the container-rendered resolution on the Pix as image metadata
        // so Tesseract can interpret text size correctly.
        pix.set_resolution(dpi, dpi)
            .map_err(tesseract_error("set the OCR image resolution"))?;

        // Give Tesseract the Leptonica image. `set_image_2` borrows the Pix
        // pointer; keep `pix` alive for the rest of this method.
        self.api
            .set_image_2(pix.as_ptr())
            .map_err(tesseract_error("set the image"))?;

        self.api
            .recognize()
            .map_err(tesseract_error("run text recognition"))?;

        let iterator = self
            .api
            .get_iterator()
            .map_err(tesseract_error("get the result iterator"))?;

        Ok(OcrPage::new(extract_ocr_words(&iterator)?))
    }
}

impl XbergTesseractOcr {
    /// Create instance of `XbergTesseractOcr`.
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
    /// instance of a `XbergTesseractWorker` containing a Tesseract object.
    fn ocr_pages_parallel(&self, pages: &[PageData]) -> Result<Vec<OcrPage>, OcrError> {
        // Create pool of Rayon workers.
        let pool = ThreadPoolBuilder::new()
            .num_threads(Self::max_workers())
            .build()
            .map_err(|err| OcrError::ThreadPool(err.into()))?;

        // Set previous initiated pool to run closure.
        pool.install(|| {
            pages
                .par_iter() // Convert iter into Rayon parallel iterator.
                .map_init(
                    // Each Rayon worker gets its own `XbergTesseractOcrWorker`,
                    // created lazily on its first page. If creating it fails, we
                    // return that error and let `collect()` stop the iteration.
                    || None,
                    |ocr_worker: &mut Option<XbergTesseractOcrWorker>, page| {
                        let worker = match ocr_worker {
                            Some(worker) => worker,
                            None => ocr_worker.insert(XbergTesseractOcrWorker::new()?),
                        };
                        worker.ocr_page(page.pixels(), page.width(), page.height())
                    },
                )
                .collect::<Result<Vec<OcrPage>, OcrError>>()
        })
    }
}

impl OcrBackend for XbergTesseractOcr {
    fn ocr_pages(&self, pages: &[PageData]) -> Result<Vec<OcrPage>, OcrError> {
        self.ocr_pages_parallel(pages)
    }
}

/// Wrap a Tesseract error, saying what we were trying to do.
fn tesseract_error(action: &'static str) -> impl FnOnce(TesseractError) -> OcrError {
    move |err| OcrError::Tesseract {
        action,
        source: Box::new(err),
    }
}

/// Extract OCR words and their properties.
///
/// Uses `xberg-tesseract`'s high-level iterator helper instead of local
/// low-level Tesseract bindings.
fn extract_ocr_words(iterator: &ResultIterator) -> Result<Vec<OcrWord>, OcrError> {
    let words = iterator
        .extract_all_words()
        .map_err(tesseract_error("extract words from the result iterator"))?
        // Words that Tesseract returned unusable data for are left out. The
        // text layer is a best effort, so it's better than failing the page.
        .words;

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
    use super::XbergTesseractOcrWorker;

    #[test]
    fn initializes_with_tesseract_data() {
        XbergTesseractOcrWorker::new()
            .expect("Tesseract data should be available on every supported platform");
    }
}
