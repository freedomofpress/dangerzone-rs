//! PDF rendering helpers for invisible OCR text layers.

use anyhow::Result;
use std::fmt::Write;

use super::OcrPage;
use crate::DPI;

/// Original source of this file:
/// - https://github.com/tesseract-ocr/tesseract/blob/main/src/api/pdf_ttf.h
/// - https://github.com/tesseract-ocr/tesseract/blob/main/tessdata/pdf.ttf
///
/// And can manually be built with: `bin2cpp pdf.ttf pdf_ttf cpp17`
const GLYPHLESS_PDF_TTF: &[u8] = include_bytes!("../../assets/pdf.ttf");

/// Encode OCR text so our glyphless font can understand it
///
/// Our OCR font uses /Identity-H which expects each character to
/// be represented as a 16-bit hex.
fn text_to_utf16be_hex(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 4);
    for unit in text.encode_utf16() {
        let _ = write!(out, "{unit:04X}");
    }
    out
}

/// Embed glyphless OCR font objects in PDF
///
/// These objects are embedded once into the PDF and referenced
/// by `/OcrFont`.
//
// TODO: Currently this method contains blocks of code constructing the several font objects to
// embed in the PDF. I notice relations between these font objects like e.g object 3 (Type0)
// referencing object 4 (CID font). I want to make different types/structs like Type0FontObject,
// CidFontObject,... to make these objects better represented in the code.
pub(crate) fn embed_ocr_font(
    pdf_data: &mut Vec<u8>,          // Raw PDF data
    object_offsets: &mut Vec<usize>, // Byte positions of each new object. Used to write the PDF xref table.
) -> Result<()> {
    // Object 3: Type0 font. Wrapper for character text to route
    // character codes to correct descendant font.
    object_offsets.push(pdf_data.len());
    // Start of object 3
    pdf_data.extend_from_slice(b"3 0 obj\n");
    // Start of PDF dictionary.
    pdf_data.extend_from_slice(b"<<\n");
    // GlyphlessFont as Basefont.
    pdf_data.extend_from_slice(b" /BaseFont /GlyphLessFont\n");
    // Reference to object 4 containing actual descendant font.
    pdf_data.extend_from_slice(b" /DescendantFonts [ 4 0 R ]\n");
    // Use identity mapping for character codes.
    pdf_data.extend_from_slice(b" /Encoding /Identity-H\n");
    // Declare font subtype. Type0 is the composite font containing multiple CID fonts. This way we
    // can support a wide range of Unicode characters.
    pdf_data.extend_from_slice(b" /Subtype /Type0\n");
    // Declare this object as a Font.
    pdf_data.extend_from_slice(b" /Type /Font\n");
    // End PDF dictionary.
    pdf_data.extend_from_slice(b">>\n");
    // End object.
    pdf_data.extend_from_slice(b"endobj\n");

    // Object 4: The actual CID font implementation.
    // A CID font is a Character Identifier which is actually an integer identifying the character.
    // Not necessarily the glyph or unicode itself.
    object_offsets.push(pdf_data.len());
    // Start of object 4.
    pdf_data.extend_from_slice(b"4 0 obj\n");
    // Start PDF dictionary
    pdf_data.extend_from_slice(b"<<\n");
    // Also the actual CID font needs to be identified as base font
    pdf_data.extend_from_slice(b" /BaseFont /GlyphLessFont\n");
    // Define CIDSystemInfo. This defines the CID character collection identity. A CID is just an
    // integer, we need the correct info about what system we use to convert these integers to the
    // actual characters.
    pdf_data.extend_from_slice(
        b" /CIDSystemInfo << /Ordering (Identity) /Registry (Adobe) /Supplement 0 >>\n",
    );
    // Per character advance widths.
    pdf_data.extend_from_slice(b" /DW 500 \n");
    // Link to object 5 containing font metadata.
    pdf_data.extend_from_slice(b" /FontDescriptor 5 0 R\n");
    // Subtype saying this is a CID font using TrueType outlines.
    pdf_data.extend_from_slice(b" /Subtype /CIDFontType2\n");
    // Declare object 4 as font.
    pdf_data.extend_from_slice(b" /Type /Font\n");
    // End dictionary.
    pdf_data.extend_from_slice(b">>\n");
    // End object.
    pdf_data.extend_from_slice(b"endobj\n");

    // Object 5: Font metadata and descriptors like width, metrics, characteristics,...
    // Without this data selection rectangles, cursor geometry,... wouldn't be possible.
    object_offsets.push(pdf_data.len());
    // Start object 5.
    pdf_data.extend_from_slice(b"5 0 obj\n");
    // Start PFD dictionary.
    pdf_data.extend_from_slice(b"<<\n");
    // Height above baseline. 1000 is 1em and basic config.
    pdf_data.extend_from_slice(b" /Ascent 1000\n");
    // Height of an uppercase char.
    pdf_data.extend_from_slice(b" /CapHeight 1000\n");
    // Bitfield 1 to only support basic monospace for our PoC.
    // TODO: Also support symbolic later.
    pdf_data.extend_from_slice(b" /Flags 1\n");
    // Bounding box for glyph matching DW 500 and Ascent 1000.
    pdf_data.extend_from_slice(b" /FontBBox [ 0 0 500 1000 ]\n");
    // Reference object 6 containing embedded TrueFont font.
    pdf_data.extend_from_slice(b" /FontFile2 6 0 R\n");
    // Internal font name matching Type0 and CID.
    pdf_data.extend_from_slice(b" /FontName /GlyphLessFont\n");
    // Declare this object as Font descriptir.
    pdf_data.extend_from_slice(b" /Type /FontDescriptor\n");
    // End dictionary.
    pdf_data.extend_from_slice(b">>\n");
    // End object.
    pdf_data.extend_from_slice(b"endobj\n");

    // Object 6: Embed our included Tesseract TrueType font file/program.
    object_offsets.push(pdf_data.len());
    pdf_data.extend_from_slice(b"6 0 obj\n");
    pdf_data.extend_from_slice(b"<<\n");
    pdf_data.extend_from_slice(format!(" /Length {}\n", GLYPHLESS_PDF_TTF.len()).as_bytes());
    pdf_data.extend_from_slice(format!(" /Length1 {}\n", GLYPHLESS_PDF_TTF.len()).as_bytes());
    pdf_data.extend_from_slice(b">>\n");
    pdf_data.extend_from_slice(b"stream\n");
    pdf_data.extend_from_slice(GLYPHLESS_PDF_TTF);
    pdf_data.extend_from_slice(b"\nendstream\n");
    pdf_data.extend_from_slice(b"endobj\n");

    Ok(())
}

/// Append invisible OCR text operations to a page content stream.
pub(crate) fn append_ocr_text_layer(content: &mut String, ocr_page: &OcrPage, height_pts: f32) {
    // OCR gives word boxes in page pixels, measured from the top-left.
    // PDF text positions use points, measured from the bottom-left, so
    // each word position must be scaled and flipped vertically.
    let scale = 72.0 / DPI as f32;

    // This is a hardcoded const used for calibration to determine how wide the PDF would
    // make a hidden word. If we change font metrics of our OCR fonts like `/ DW` this
    // calibration needs to be adapted again.
    const GLYPHLESS_CHAR_WIDTH: f32 = 2.0;

    for word in ocr_page.words() {
        let text = word.text.trim();
        let char_count = text.chars().count();
        if char_count == 0 || word.vbox.w <= 0 || word.vbox.h <= 0 {
            continue;
        }

        let x_pts = word.vbox.x as f32 * scale;
        let y_pts = height_pts - ((word.vbox.y + word.vbox.h) as f32 * scale);
        let font_size = (word.vbox.h as f32 * scale).max(1.0);
        let word_width_pts = (word.vbox.w as f32 * scale).max(1.0);
        // Estimate how wide the glyphless font would make this text without Tz.
        let natural_text_width_pts = font_size * char_count as f32 / GLYPHLESS_CHAR_WIDTH;
        // Convert desired-width / natural-width into the percentage expected by Tz.
        let horizontal_scale_percent = 100.0 * word_width_pts / natural_text_width_pts;
        // Keep pathological OCR boxes or font sizes from producing unusable scaling.
        let horizontal_scale = horizontal_scale_percent.clamp(5.0, 300.0);
        // Convert text to 16-bit hex representation which our Type0 font can
        // understand.
        let text_hex = text_to_utf16be_hex(text);

        // Rendering mode 3 adds invisible text to the page.
        // With Tz we set the ratio in percentage of how much we want to stretch the
        // invisible box to match the visual word.
        content.push_str(&format!(
                    "BT\n3 Tr\n/OcrFont {font_size:.2} Tf\n{horizontal_scale:.2} Tz\n1 0 0 1 {x_pts:.2} {y_pts:.2} Tm\n<{text_hex}> Tj\nET\n"
                ));
    }
}
