//! Error types returned by the library.

use std::fmt;

use crate::{MAX_PAGES, MAX_PAGE_HEIGHT, MAX_PAGE_WIDTH};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

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
