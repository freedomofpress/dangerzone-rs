//! General purpose helper methods used in the application

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// Replace characters that are unsafe to print in a terminal with U+FFFD (�).
///
/// This covers control characters such as ANSI escape codes, invisible
/// formatting characters, private use and unassigned code points, and line
/// and paragraph separators. Use it on any untrusted text, such as file names
/// or the container's output, before printing it.
///
/// `\n` is kept if `keep_newlines` is true.
///
/// ```
/// use dangerzone_rs::replace_control_chars;
///
/// assert_eq!(replace_control_chars("\x1b[31mred\n", false), "\u{FFFD}[31mred\u{FFFD}");
/// assert_eq!(replace_control_chars("\x1b[31mred\n", true), "\u{FFFD}[31mred\n");
/// ```
pub fn replace_control_chars(s: &str, keep_newlines: bool) -> String {
    /// Return whether Unicode character is safe to print in a terminal
    /// emulator, based on its General Category
    fn is_safe(c: char) -> bool {
        !matches!(
            unicode_general_category::get_general_category(c),
            unicode_general_category::GeneralCategory::Control // Cc
            | unicode_general_category::GeneralCategory::Format // Cf
            | unicode_general_category::GeneralCategory::PrivateUse // Co
            | unicode_general_category::GeneralCategory::Unassigned // Cn
            | unicode_general_category::GeneralCategory::LineSeparator // Zl
            | unicode_general_category::GeneralCategory::ParagraphSeparator // Zp
        )
    }

    s.chars()
        .map(|c| {
            if is_safe(c) || (keep_newlines && c == '\n') {
                c
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

/// A value that may be controlled by an attacker, such as a document's name
/// or the container's output.
///
/// Wrap such values as soon as they enter the program. Printing it with `{}`
/// or `{:?}` passes it through [`replace_control_chars`], without keeping
/// newlines, so it is safe to show in a terminal. Use
/// [`sanitized`](Self::sanitized) to keep newlines.
///
/// The original value can't be taken out. Instead, `Untrusted` has methods
/// for the few things that need it, e.g. [`read`](Self::read) to read the
/// file at an untrusted path.
///
/// ```
/// use std::path::PathBuf;
/// use dangerzone_rs::Untrusted;
///
/// let path = Untrusted::new(PathBuf::from("\x1b[31mred\n.pdf"));
/// assert_eq!(path.to_string(), "\u{FFFD}[31mred\u{FFFD}.pdf");
/// ```
#[derive(Clone, Copy)]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Wrap an attacker-controlled value.
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

impl<P: Into<PathBuf>> From<P> for Untrusted<PathBuf> {
    fn from(path: P) -> Self {
        Self(path.into())
    }
}

impl<P: AsRef<Path>> Untrusted<P> {
    /// Read the whole file at this path.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        fs::read(&self.0)
    }

    /// Create the file at this path for writing, or truncate it if it exists.
    pub fn create(&self) -> io::Result<File> {
        File::create(&self.0)
    }
}

impl<T: AsRef<OsStr>> Untrusted<T> {
    /// The value with [`replace_control_chars`] applied.
    pub fn sanitized(&self, keep_newlines: bool) -> String {
        replace_control_chars(&self.0.as_ref().to_string_lossy(), keep_newlines)
    }
}

impl<T: AsRef<OsStr>> fmt::Display for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sanitized(false))
    }
}

impl<T: AsRef<OsStr>> fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Untrusted").field(&self.to_string()).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use testresult::TestResult;

    use super::{replace_control_chars, Untrusted};

    /// Test cases for test_replace_control_chars containing tuples
    /// with format (input, expected_newlines_no_preserve,
    /// expected_newlines_preserve)
    fn sanitize_test_cases() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            // ANSI escape bytes are replaced
            (
                "\x1b[31mANSI escaped red text.\x1b[0m",
                "\u{FFFD}[31mANSI escaped red text.\u{FFFD}[0m",
                "\u{FFFD}[31mANSI escaped red text.\u{FFFD}[0m",
            ),
            // Verify newline preserve mode
            (
                "\x1b[31mANSI escaped\nred text.\x1b[0m",
                "\u{FFFD}[31mANSI escaped\u{FFFD}red text.\u{FFFD}[0m",
                "\u{FFFD}[31mANSI escaped\nred text.\u{FFFD}[0m",
            ),
            // Tab and carriage-return control sanitizing
            (
                "tab:\tcarriage:\r",
                "tab:\u{FFFD}carriage:\u{FFFD}",
                "tab:\u{FFFD}carriage:\u{FFFD}",
            ),
            // Safe unicode passes
            ("plain ✓ café 😀", "plain ✓ café 😀", "plain ✓ café 😀"),
            // Non-printing and reserved codes are replaced
            (
                "a\u{200E}b\u{E000}c\u{0378}d\u{2028}e\u{2029}f",
                "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f",
                "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f",
            ),
            // Literal '\n' is optionally preserved. line and paragraph separators are not
            (
                "x\n\u{2028}\u{2029}y",
                "x\u{FFFD}\u{FFFD}\u{FFFD}y",
                "x\n\u{FFFD}\u{FFFD}y",
            ),
            // Mixed content validates newline handling
            (
                "ok line\n\x1b[31mred\x1b[0m\nend",
                "ok line\u{FFFD}\u{FFFD}[31mred\u{FFFD}[0m\u{FFFD}end",
                "ok line\n\u{FFFD}[31mred\u{FFFD}[0m\nend",
            ),
        ]
    }

    #[test]
    fn test_replace_control_chars() {
        for (input, expected_newlines_no_preserve, expected_newlines_preserve) in
            sanitize_test_cases()
        {
            assert_eq!(
                replace_control_chars(input, false),
                expected_newlines_no_preserve,
                "replace_control_chars(false) failed for input: {input:?}",
            );
            assert_eq!(
                replace_control_chars(input, true),
                expected_newlines_preserve,
                "replace_control_chars(true) failed for input: {input:?}",
            );
        }
    }

    #[test]
    fn test_untrusted_is_sanitized_when_printed() {
        let raw = "dir/\x1b[31mevil\n.pdf";
        let expected = "dir/\u{FFFD}[31mevil\u{FFFD}.pdf";

        let text = Untrusted::new(raw);
        assert_eq!(text.to_string(), expected);
        assert_eq!(format!("{text:?}"), format!("Untrusted({expected:?})"));
        assert_eq!(text.sanitized(true), "dir/\u{FFFD}[31mevil\n.pdf");

        let path = Untrusted::new(PathBuf::from(raw));
        assert_eq!(path.to_string(), expected);
    }

    #[test]
    fn test_untrusted_path_from() {
        let raw = "\x1b[31mevil\n.pdf";
        let expected = "\u{FFFD}[31mevil\u{FFFD}.pdf";

        let from_str: Untrusted<PathBuf> = raw.into();
        let from_path_buf: Untrusted<PathBuf> = PathBuf::from(raw).into();
        assert_eq!(from_str.to_string(), expected);
        assert_eq!(from_path_buf.to_string(), expected);
    }

    #[test]
    fn test_untrusted_path_create_and_read() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = Untrusted::new(dir.path().join("\x1b[31mevil\n.pdf"));

        path.create()?.write_all(b"data")?;
        assert_eq!(path.read()?, b"data");

        path.create()?;
        assert_eq!(path.read()?, b"");
        Ok(())
    }
}
