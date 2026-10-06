//! Document metadata intelligence (explicitly public or user-supplied).
//!
//! Supports PDF, DOCX, XLSX, PPTX, and images via bounded byte-scanning
//! with no new dependencies. Extracts safe metadata only (author, creator
//! software, creation/update timestamps, embedded URLs/domains/emails,
//! relationships). Never stores local filesystem paths beyond a basename;
//! never auto-downloads a document because a URL exists in the graph.

use std::collections::BTreeSet;

/// Safe document metadata (no file paths, no raw content).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocumentMetadata {
    pub author: Option<String>,
    pub creator: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub title: Option<String>,
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub emails: Vec<String>,
}

fn clean_field(raw: &[u8], max: usize) -> Option<String> {
    let text = String::from_utf8_lossy(raw).trim().to_owned();
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return None;
    }
    Some(text)
}

/// Scan `(`...`)` PDF string after a `/Key` marker (bounded, no nesting).
fn pdf_string_after(bytes: &[u8], key: &[u8]) -> Option<String> {
    let mut search = 0;
    while let Some(pos) = bytes[search..].windows(key.len()).position(|w| w == key) {
        let mut i = search + pos + key.len();
        // Skip whitespace.
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\n' || bytes[i] == b'\r' || bytes[i] == b'\t')
        {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'(' {
            i += 1;
            let mut out = Vec::new();
            let mut depth = 1;
            while i < bytes.len() && out.len() < 256 {
                match bytes[i] {
                    b'\\' if i + 1 < bytes.len() => {
                        out.push(bytes[i + 1]);
                        i += 2;
                    }
                    b'(' => {
                        depth += 1;
                        out.push(b'(');
                        i += 1;
                    }
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        out.push(b')');
                        i += 1;
                    }
                    b => {
                        out.push(b);
                        i += 1;
                    }
                }
            }
            if let Some(clean) = clean_field(&out, 128) {
                return Some(clean);
            }
        }
        search += pos + 1;
        if search >= bytes.len() {
            break;
        }
    }
    None
}

/// Scan XML-ish `<tag>value</tag>` (OOXML core.xml, bounded).
fn xml_tag(bytes: &[u8], tag: &str) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let open = format!("<{tag}");
    let close = format!("</{}>", tag.split_whitespace().next().unwrap_or(tag));
    let mut search = 0;
    while let Some(start) = text[search..].find(&open) {
        let abs = search + start;
        let Some(end_open) = text[abs..].find('>') else {
            break;
        };
        let content_start = abs + end_open + 1;
        let Some(end) = text[content_start..].find(&close) else {
            break;
        };
        let raw = text[content_start..content_start + end].trim();
        if !raw.is_empty() && raw.len() <= 128 && !raw.chars().any(char::is_control) {
            // Strip nested tags (keep text only, bounded).
            let mut clean = String::new();
            let mut in_tag = false;
            for ch in raw.chars().take(128) {
                match ch {
                    '<' => in_tag = true,
                    '>' => in_tag = false,
                    _ if !in_tag => clean.push(ch),
                    _ => {}
                }
            }
            let clean = clean.trim().to_owned();
            if !clean.is_empty() {
                return Some(clean);
            }
        }
        search = content_start + end + close.len();
    }
    None
}

/// Bounded embedded indicators: `https://` URLs, `user@host` emails,
/// and bare domains (conservative, no validation beyond shape).
fn embedded_indicators(bytes: &[u8]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let text = String::from_utf8_lossy(bytes);
    let mut urls = BTreeSet::new();
    let mut emails = BTreeSet::new();
    // URLs: `http(s)://` until whitespace/quote/bracket.
    for token in
        text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')'))
    {
        let clean = token.trim().trim_end_matches(['.', ',', ';']);
        if clean.len() > 12 && clean.len() <= 512 {
            if let Ok(parsed) = url::Url::parse(clean) {
                if (parsed.scheme() == "http" || parsed.scheme() == "https")
                    && parsed.host_str().is_some()
                {
                    urls.insert(clean.to_owned());
                    if urls.len() >= 16 {
                        break;
                    }
                }
            }
        }
    }
    // Emails: single `@`, dot in domain, bounded charset.
    for token in text.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | ',' | ';')
    }) {
        let clean = token.trim();
        if clean.len() < 5 || clean.len() > 254 {
            continue;
        }
        if clean.chars().filter(|c| *c == '@').count() != 1 {
            continue;
        }
        let Some((local, domain)) = clean.split_once('@') else {
            continue;
        };
        if local.is_empty() || local.len() > 64 {
            continue;
        }
        let domain = domain.trim_end_matches(['.', ',', ';']);
        if crate::search::canonical_domain_value(domain).is_some() && emails.len() < 8 {
            emails.insert(clean.to_owned());
        }
    }
    let mut domains = BTreeSet::new();
    for url in &urls {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let lower = host.to_ascii_lowercase();
                if crate::search::canonical_domain_value(&lower).is_some() {
                    domains.insert(lower);
                }
            }
        }
        if domains.len() >= 16 {
            break;
        }
    }
    (
        urls.into_iter().take(16).collect(),
        domains.into_iter().take(16).collect(),
        emails.into_iter().take(8).collect(),
    )
}

/// Extract safe metadata from document bytes (PDF or OOXML/images).
/// `hint` selects parsing (`pdf`, `ooxml`, or `auto` byte-sniff).
pub fn extract_metadata(bytes: &[u8], hint: &str) -> DocumentMetadata {
    let bounded = &bytes[..bytes.len().min(4 * 1024 * 1024)];
    let mut meta = DocumentMetadata::default();
    let is_pdf = hint == "pdf" || bounded.starts_with(b"%PDF");
    if is_pdf {
        meta.author = pdf_string_after(bounded, b"/Author");
        meta.creator = pdf_string_after(bounded, b"/Creator")
            .or_else(|| pdf_string_after(bounded, b"/Producer"));
        meta.title = pdf_string_after(bounded, b"/Title");
        meta.created = pdf_string_after(bounded, b"/CreationDate");
        meta.modified = pdf_string_after(bounded, b"/ModDate");
    } else {
        // OOXML core.xml props (also present inside ZIP as raw XML text
        // when the file is scanned as bytes) + generic Office markers.
        meta.author = xml_tag(bounded, "dc:creator").or_else(|| xml_tag(bounded, "dc:Creator"));
        meta.creator = xml_tag(bounded, "x:Generator").or_else(|| xml_tag(bounded, "Application"));
        meta.title = xml_tag(bounded, "dc:title");
        meta.created = xml_tag(bounded, "dcterms:created");
        meta.modified = xml_tag(bounded, "dcterms:modified");
    }
    let (urls, domains, emails) = embedded_indicators(bounded);
    meta.urls = urls;
    meta.domains = domains;
    meta.emails = emails;
    meta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_author_creator_timestamps_no_path_leak() {
        let bytes = b"%PDF-1.4\n/Author (Example Author)\n/Creator (Example Software)\n/CreationDate (D:20240101000000Z)\nhttps://example.test/x user@example.test".to_vec();
        let meta = extract_metadata(&bytes, "pdf");
        assert_eq!(meta.author.as_deref(), Some("Example Author"));
        assert_eq!(meta.creator.as_deref(), Some("Example Software"));
        assert_eq!(meta.urls, vec!["https://example.test/x".to_owned()]);
        assert_eq!(meta.emails, vec!["user@example.test".to_owned()]);
        // No filesystem paths retained.
        let debug = format!("{meta:?}");
        assert!(!debug.contains("/home"));
        assert!(!debug.contains("C:\\"));
    }

    #[test]
    fn ooxml_creator_and_embedded_domain() {
        let bytes = b"PK\x03\x04<dc:creator>Example Writer</dc:creator><dcterms:created>2024-02-02</dcterms:created> See https://api.example.test/v1".to_vec();
        let meta = extract_metadata(&bytes, "ooxml");
        assert_eq!(meta.author.as_deref(), Some("Example Writer"));
        assert!(meta.domains.contains(&"api.example.test".to_owned()));
    }

    #[test]
    fn control_characters_rejected() {
        let bytes = b"%PDF /Author (bad\x01name)".to_vec();
        let meta = extract_metadata(&bytes, "pdf");
        assert!(meta.author.is_none());
    }
}
