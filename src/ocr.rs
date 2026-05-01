use crate::{PageData, DPI};
use anyhow::{Context, Result};
use kreuzberg_tesseract::{TessPageSegMode, TesseractAPI};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OcrBackend {
    Kreuzberg,
    Ocrmypdf,
}

#[derive(Clone, Debug)]
pub struct OcrWord {
    pub text: String,
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

pub type OcrTextLayer = Vec<OcrWord>;

pub trait OcrEngine {
    fn recognize_pages(&self, pages: &[PageData]) -> Result<Vec<OcrTextLayer>>;
}

#[derive(Clone, Debug)]
pub struct TesseractOcrEngine {
    language: String,
    tessdata_dir: PathBuf,
}

impl TesseractOcrEngine {
    pub fn from_env() -> Self {
        let language = std::env::var("DANGERZONE_OCR_LANG").unwrap_or_else(|_| "eng".to_string());
        let tessdata_dir = resolve_tessdata_dir(&language);
        Self {
            language,
            tessdata_dir,
        }
    }

    pub fn new(language: impl Into<String>, tessdata_dir: impl Into<PathBuf>) -> Self {
        Self {
            language: language.into(),
            tessdata_dir: tessdata_dir.into(),
        }
    }

    fn recognize_page(&self, page: &PageData, page_idx: usize) -> Result<OcrTextLayer> {
        eprintln!("Running OCR on page {}...", page_idx + 1);
        if page.width == 0 || page.height == 0 {
            anyhow::bail!("Cannot OCR a page with zero width or height");
        }

        let api = TesseractAPI::new().context("Failed to create Tesseract API")?;
        api.init(&self.tessdata_dir, &self.language)
            .with_context(|| {
                format!(
                    "Failed to initialize Tesseract with language '{}' and tessdata path '{}'",
                    self.language,
                    self.tessdata_dir.display()
                )
            })?;
        api.set_page_seg_mode(TessPageSegMode::PSM_AUTO)
            .context("Failed to configure Tesseract page segmentation mode")?;
        api.set_image(
            &page.pixels,
            i32::from(page.width),
            i32::from(page.height),
            3,
            i32::from(page.width) * 3,
        )
        .context("Failed to pass page pixels to Tesseract")?;
        api.set_source_resolution(DPI.round() as i32)
            .context("Failed to set Tesseract source resolution")?;

        api.recognize().context("Failed to recognize page text")?;
        let tsv = api
            .get_tsv_text(0)
            .context("Failed to extract OCR TSV output")?;
        let lines = parse_tesseract_tsv_words(&tsv);
        eprintln!(
            "OCR found {} text line(s) on page {}",
            lines.len(),
            page_idx + 1
        );
        Ok(lines)
    }
}

impl OcrEngine for TesseractOcrEngine {
    fn recognize_pages(&self, pages: &[PageData]) -> Result<Vec<OcrTextLayer>> {
        if pages.is_empty() {
            return Ok(Vec::new());
        }

        configure_tesseract_worker_threads();
        let worker_count = ocr_worker_count(pages.len());
        let (sender, receiver) = mpsc::channel();

        std::thread::scope(|scope| {
            for worker_idx in 0..worker_count {
                let sender = sender.clone();
                scope.spawn(move || {
                    for page_idx in (worker_idx..pages.len()).step_by(worker_count) {
                        let result = self.recognize_page(&pages[page_idx], page_idx);
                        if sender.send((page_idx, result)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(sender);
        });

        let mut layers = Vec::with_capacity(pages.len());
        layers.resize_with(pages.len(), || None);
        for (page_idx, result) in receiver {
            layers[page_idx] = Some(result?);
        }

        layers
            .into_iter()
            .enumerate()
            .map(|(page_idx, layer)| {
                layer.with_context(|| format!("OCR worker did not return page {}", page_idx + 1))
            })
            .collect()
    }
}

fn configure_tesseract_worker_threads() {
    if std::env::var_os("OMP_THREAD_LIMIT").is_none() {
        std::env::set_var("OMP_THREAD_LIMIT", "1");
    }
    if std::env::var_os("OMP_NUM_THREADS").is_none() {
        std::env::set_var("OMP_NUM_THREADS", "1");
    }
}

fn ocr_worker_count(page_count: usize) -> usize {
    if page_count == 0 {
        return 0;
    }

    let cpu_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let worker_count = (cpu_count + 1) / 2;
    worker_count.max(1).min(page_count)
}

fn parse_tesseract_tsv_words(tsv: &str) -> Vec<OcrWord> {
    #[derive(Default)]
    struct OcrLine {
        words: Vec<(i32, String)>,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
        initialized: bool,
    }

    let mut lines: BTreeMap<(i32, i32, i32, i32), OcrLine> = BTreeMap::new();

    for line in tsv.lines().skip(1) {
        let mut fields = line.split('\t');
        let level = match fields.next().and_then(|field| field.parse::<u8>().ok()) {
            Some(level) => level,
            None => continue,
        };
        if level != 5 {
            continue;
        }

        let page_num = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let block_num = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let par_num = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let line_num = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        fields.next(); // word_num

        let raw_left = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let raw_top = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let raw_width = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let raw_height = match fields.next().and_then(|field| field.parse::<i32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let confidence = match fields.next().and_then(|field| field.parse::<f32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let text = fields.collect::<Vec<_>>().join("\t").trim().to_string();

        if text.is_empty() || confidence < 0.0 || raw_width <= 0 || raw_height <= 0 {
            continue;
        }

        let entry = lines
            .entry((page_num, block_num, par_num, line_num))
            .or_default();
        let left = raw_left;
        let top = raw_top;
        let right = raw_left + raw_width;
        let bottom = raw_top + raw_height;
        if entry.initialized {
            entry.left = entry.left.min(left);
            entry.top = entry.top.min(top);
            entry.right = entry.right.max(right);
            entry.bottom = entry.bottom.max(bottom);
        } else {
            entry.left = left;
            entry.top = top;
            entry.right = right;
            entry.bottom = bottom;
            entry.initialized = true;
        }
        entry.words.push((left, text));
    }

    lines
        .into_values()
        .filter_map(|mut line| {
            line.words.sort_by_key(|(left, _)| *left);
            let text = line
                .words
                .into_iter()
                .map(|(_, text)| text)
                .collect::<Vec<_>>()
                .join(" ");
            if text.is_empty() || !line.initialized {
                return None;
            }
            Some(OcrWord {
                text,
                left: line.left,
                top: line.top,
                right: line.right,
                bottom: line.bottom,
            })
        })
        .collect()
}

fn resolve_tessdata_dir(language: &str) -> PathBuf {
    let first_language = language.split('+').next().unwrap_or("eng");

    if let Ok(prefix) = std::env::var("TESSDATA_PREFIX") {
        let path = PathBuf::from(prefix);
        if has_traineddata(&path, first_language) {
            return path;
        }
        let nested = path.join("tessdata");
        if has_traineddata(&nested, first_language) {
            return nested;
        }
        return path;
    }

    let mut candidates = Vec::new();
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join("share").join("tessdata"));
            candidates.push(exe_dir.join("..").join("share").join("tessdata"));
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join("share").join("tessdata"));
    }

    candidates.extend([
        PathBuf::from("/usr/share/tessdata"),
        PathBuf::from("/usr/share/tesseract/tessdata"),
        PathBuf::from("/usr/share/tesseract-ocr/tessdata"),
        PathBuf::from("/usr/share/tesseract-ocr/5/tessdata"),
        PathBuf::from("/usr/share/tesseract-ocr/4.00/tessdata"),
        PathBuf::from("/usr/local/share/tessdata"),
        PathBuf::from("/opt/homebrew/share/tessdata"),
    ]);

    if let Ok(home) = std::env::var("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join(".kreuzberg-tesseract")
                .join("tessdata"),
        );
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        candidates.push(
            PathBuf::from(appdata)
                .join("kreuzberg-tesseract")
                .join("tessdata"),
        );
    }

    candidates
        .into_iter()
        .find(|path| has_traineddata(path, first_language))
        .unwrap_or_default()
}

fn has_traineddata(path: &Path, language: &str) -> bool {
    path.join(format!("{language}.traineddata")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocr_worker_count_is_bounded_by_pages() {
        assert_eq!(ocr_worker_count(0), 0);
        assert_eq!(ocr_worker_count(1), 1);
        assert!(ocr_worker_count(2) <= 2);
    }

    #[test]
    fn test_parse_tesseract_tsv_groups_words_by_line() {
        let tsv = concat!(
            "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n",
            "5\t1\t1\t1\t1\t1\t10\t20\t30\t10\t96\tHello\n",
            "5\t1\t1\t1\t1\t2\t45\t22\t25\t10\t95\tworld\n",
            "5\t1\t1\t1\t2\t1\t12\t50\t18\t10\t93\tNext\n",
            "5\t1\t1\t1\t2\t2\t35\t51\t20\t10\t-1\tignored\n",
        );

        let words = parse_tesseract_tsv_words(tsv);

        assert_eq!(words.len(), 2);
        assert_eq!(words[0].text, "Hello world");
        assert_eq!(words[0].left, 10);
        assert_eq!(words[0].top, 20);
        assert_eq!(words[0].right, 70);
        assert_eq!(words[0].bottom, 32);
        assert_eq!(words[1].text, "Next");
    }
}
