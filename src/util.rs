//! General purpose helper methods used in the application

/// Remove control characters from string. Protects a terminal emulator
/// from obscure control characters
///
/// Control characters are replaced by � U+FFFD Replacement Character
pub(crate) fn replace_control_chars(s: &str, keep_newlines: bool) -> String {
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

#[cfg(test)]
mod tests {
    use super::replace_control_chars;

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
}
