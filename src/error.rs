//! Error types returned by the library.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

use crate::util::Untrusted;
use crate::{IMAGE_NAME, MAX_PAGES, MAX_PAGE_HEIGHT, MAX_PAGE_WIDTH};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Until Rust stabilizes backtraces, we don't have a good way to do the
/// following:
/// 1. Fail with an std::error::Error.
/// 2. Point to the exact place where an error occurred.
/// 3. Add some extra context for this error.
///
/// The `snafu` crate exists, but it relies on preprocessor magic that makes it
/// a bit opaque. On the other hand, `thiserror` is more familiar and
/// straight-forward.
///
/// This struct is a way to have errors with contexts. Its job is to wrap
/// std::error::Error thrown by other libraries (or Rust's std), and add a
/// string as a context. Then, it must be used as a source of a higher-level
/// error. It's `pub` only because it appears in [`Error`]; the crate does not
/// export it, so callers can't name it.
///
/// In practice, this error should be used as follows:
///
/// ```ignore
/// function_that_fails()
///     .context("performing a disintegration spell")
///     .map_err(Error::Spell)
/// ```
///
/// where `.context()` will create an instance of this struct.
///
/// We suggest using context messages that explain what we were trying to do,
/// and not what failed. The failure assessment should be part of the
/// high-level error.
#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct ContextError {
    context: &'static str,
    source: BoxError,
}

/// Adds a message to errors, by wrapping them in a [`ContextError`]. Pass the
/// result to `map_err` with an [`Error`] variant.
pub(crate) trait ErrorContext<T> {
    /// Wrap the error in a [`ContextError`] with `context` as its message.
    fn context(self, context: &'static str) -> Result<T, ContextError>;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context(self, context: &'static str) -> Result<T, ContextError> {
        self.map_err(|source| ContextError {
            context,
            source: source.into(),
        })
    }
}

/// Errors returned by the conversion functions.
///
/// Paths in errors are [`Untrusted`], so the messages are safe to print.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Podman could not be run.
    #[error("failed to run podman; make sure it is installed and in your PATH")]
    PodmanCommand(#[source] io::Error),

    /// Podman ran, but could not start the container. Podman's own error is
    /// printed to stderr.
    #[error(
        "podman could not start the container ({0}); make sure the image \
         '{IMAGE_NAME}' is pulled"
    )]
    ContainerRun(ExitStatus),

    /// Sending the document to the container or reading its output failed.
    #[error("failed to communicate with the container")]
    ContainerIo(#[source] ContextError),

    /// Encountered an issue while logging a message.
    #[error("failed to write to log")]
    Log(#[source] ContextError),

    /// The document converter in the container exited with a non-zero
    /// status.
    #[error(
        "container failed with {0}; the document format may be unsupported \
         or corrupted"
    )]
    Conversion(ExitStatus),

    /// The container returned invalid pixel data. You can learn more about
    /// this error by consulting the `PixelDataError` variants.
    #[error("invalid pixel data from the container")]
    PixelData(#[from] PixelDataError),

    /// The input document could not be read.
    #[error("failed to read input file '{path}'")]
    InputFile {
        /// Path of the input document.
        path: Untrusted<PathBuf>,
        /// The underlying error.
        source: io::Error,
    },

    /// The PDF could not be created or written.
    #[error("failed to save the PDF to '{path}'")]
    OutputFile {
        /// Path of the PDF.
        path: Untrusted<PathBuf>,
        /// The underlying error.
        source: ContextError,
    },

    /// [`pixels_to_pdf`](crate::pixels_to_pdf) was called without pages.
    #[error("no pages to convert")]
    NoOutputPages,

    /// OCR failed.
    #[error(transparent)] // the underlying error has the actual details
    Ocr(#[from] OcrError),
}

/// Errors in the pixel stream that the container writes.
///
/// Page numbers start at 1.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PixelDataError {
    /// The stream is shorter than the page count.
    #[error("missing page count")]
    MissingPageCount,

    /// The page count is 0.
    #[error("document has no pages")]
    NoPages,

    /// The page count is above [`MAX_PAGES`].
    #[error("document has {0} pages, more than the maximum of {MAX_PAGES}")]
    TooManyPages(u16),

    /// The stream ends in the middle of a page.
    #[error("missing or truncated {field} for page {page}")]
    Truncated {
        /// The page that is cut short.
        page: u16,
        /// The page element where the stream ends.
        field: CorruptedPageField,
    },

    /// A page has invalid dimensions.
    #[error("invalid page {page}")]
    InvalidPage {
        /// The invalid page.
        page: u16,
        /// What is wrong with it.
        source: PageError,
    },

    /// There is data after the last page. Holds the number of extra bytes.
    #[error("{0} unexpected bytes after the last page")]
    TrailingData(usize),
}

/// The page element (width, height, or pixels) in the pixel stream that is
/// either missing or corrupted.
///
/// Each page in the stream is a `u16` width, a `u16` height, and then the
/// RGB pixels. This enum tells which of them could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorruptedPageField {
    /// The `u16` width.
    Width,
    /// The `u16` height.
    Height,
    /// The RGB pixels.
    Pixels,
}

impl fmt::Display for CorruptedPageField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CorruptedPageField::Width => "width",
            CorruptedPageField::Height => "height",
            CorruptedPageField::Pixels => "pixels",
        })
    }
}

/// Errors when creating a [`PageData`](crate::PageData).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageError {
    /// The width or height is 0, or above [`MAX_PAGE_WIDTH`] or
    /// [`MAX_PAGE_HEIGHT`].
    #[error(
        "page dimensions {width}x{height} are outside the allowed range of \
         1x1 to {MAX_PAGE_WIDTH}x{MAX_PAGE_HEIGHT}"
    )]
    InvalidDimensions {
        /// Width in pixels.
        width: u16,
        /// Height in pixels.
        height: u16,
    },

    /// The pixel buffer is not `width * height * 3` bytes long.
    #[error("a {width}x{height} page needs {expected} bytes of pixels, got {actual}")]
    PixelLength {
        /// Width in pixels.
        width: u16,
        /// Height in pixels.
        height: u16,
        /// `width * height * 3`.
        expected: usize,
        /// The length of the buffer.
        actual: usize,
    },
}

/// Errors from the OCR backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OcrError {
    /// A Tesseract or Leptonica call failed.
    #[error("Tesseract failed to {action}")]
    Tesseract {
        /// What we were trying to do, e.g. "run text recognition".
        action: &'static str,
        /// The error from Tesseract.
        source: BoxError,
    },

    /// The thread pool for OCR could not be created.
    #[error("failed to create the OCR thread pool")]
    ThreadPool(#[source] BoxError),
}
