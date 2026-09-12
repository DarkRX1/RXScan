//! Phase 9 bounded extraction: HTML links/forms/scripts, robots.txt,
//! sitemap XML, and conservative JavaScript string literals.
//!
//! All functions here are pure (no I/O) and strictly bounded: every list has
//! a cap, every value a length cap, every input an implied byte cap enforced
//! by callers before invoking. Malformed input yields fewer candidates —
//! never a panic, never unbounded allocation.
//!
//! The scanner is a hand-rolled byte walker, not a full HTML5 parser: it
//! understands tags, quoted/unquoted attributes, comments, and raw-text
//! elements (`script`, `style`, `textarea`, `title`) well enough to extract
//! references deterministically. Anything ambiguous is dropped and counted.

/// Maximum references kept per category, per page.
pub const MAX_LINKS_PER_PAGE: usize = 100;
pub const MAX_FORMS_PER_PAGE: usize = 20;
pub const MAX_SCRIPTS_PER_PAGE: usize = 20;
pub const MAX_IMAGES_PER_PAGE: usize = 50;
pub const MAX_INPUTS_PER_FORM: usize = 50;
/// Maximum attributes scanned per tag (prevents pathological tags).
pub const MAX_ATTRS_PER_TAG: usize = 64;
/// Maximum bytes kept per attribute value; longer values are dropped.
pub const MAX_ATTR_VALUE_LEN: usize = 2048;
/// Maximum robots.txt bytes parsed (callers must truncate before calling).
pub const MAX_ROBOTS_BYTES: usize = 32 * 1024;
/// Maximum robots.txt lines parsed.
pub const MAX_ROBOTS_LINES: usize = 2000;
/// Maximum sitemap `<loc>` entries kept per document.
pub const MAX_SITEMAP_ENTRIES: usize = 500;
/// Maximum fetched JavaScript bytes scanned for literals.
pub const MAX_JS_BYTES: usize = 64 * 1024;
/// Maximum string literals scanned per script.
pub const MAX_JS_LITERALS: usize = 200;
/// Maximum characters kept per extracted literal.
pub const MAX_LITERAL_LEN: usize = 512;

/// A raw reference found in HTML, before resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRef {
    pub value: String,
    pub truncated_value: bool,
}

/// A form with bounded field metadata. Actions are discovery evidence only —
/// forms are never submitted in Phase 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormRef {
    pub action: Option<String>,
    pub action_missing: bool,
    pub method: String,
    pub inputs: Vec<(String, String)>,
    pub inputs_truncated: bool,
}

/// Everything extracted from one HTML document, with truncation signals.
#[derive(Debug, Clone, Default)]
pub struct HtmlRefs {
    pub links: Vec<RawRef>,
    pub forms: Vec<FormRef>,
    pub scripts: Vec<RawRef>,
    pub stylesheets: Vec<RawRef>,
    pub images: Vec<RawRef>,
    pub frames: Vec<RawRef>,
    pub canonical: Option<String>,
    pub base_href: Option<String>,
    pub truncated_links: bool,
    pub truncated_forms: bool,
    pub truncated_scripts: bool,
    pub truncated_images: bool,
}

type TagAttr = (Vec<u8>, String, bool);
type ScanTagResult = (bool, Vec<u8>, Vec<TagAttr>, bool, usize);
type FormStackEntry = (Option<String>, String, Vec<(String, String)>, bool);

/// Decode the five common entities plus decimal/hex numeric references.
/// Anything else is left verbatim (conservative: never invent bytes).
fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        let tail = &rest[index..];
        let end = tail
            .find(';')
            .filter(|position| *position <= 12)
            .map(|position| index + position);
        let Some(end) = end else {
            out.push('&');
            rest = &rest[index + 1..];
            continue;
        };
        let entity = &rest[index + 1..end];
        let decoded = if entity.eq_ignore_ascii_case("amp") {
            Some("&".to_owned())
        } else if entity.eq_ignore_ascii_case("lt") {
            Some("<".to_owned())
        } else if entity.eq_ignore_ascii_case("gt") {
            Some(">".to_owned())
        } else if entity.eq_ignore_ascii_case("quot") {
            Some("\"".to_owned())
        } else if let Some(number) = entity.strip_prefix('#') {
            let codepoint = if let Some(hex) = number
                .strip_prefix('x')
                .or_else(|| number.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok()
            } else {
                number.parse::<u32>().ok()
            };
            codepoint
                .and_then(char::from_u32)
                .filter(|character| *character != '\0')
                .map(|character| character.to_string())
        } else {
            None
        };
        match decoded {
            Some(text) => out.push_str(&text),
            None => out.push_str(&rest[index..=end]),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0C)
}

fn lower_ascii(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|byte| byte.to_ascii_lowercase()).collect()
}

/// Scan one tag starting just after `<`. Returns
/// (is_end_tag, tag_name_lower, attrs, self_closing, next_position).
/// Attribute values are entity-decoded; overlong values are dropped.
fn scan_tag(bytes: &[u8], mut position: usize) -> ScanTagResult {
    let mut is_end = false;
    if position < bytes.len() && bytes[position] == b'/' {
        is_end = true;
        position += 1;
    }
    while position < bytes.len() && is_space(bytes[position]) {
        position += 1;
    }
    let name_start = position;
    while position < bytes.len()
        && !is_space(bytes[position])
        && bytes[position] != b'/'
        && bytes[position] != b'>'
    {
        position += 1;
    }
    let name = lower_ascii(&bytes[name_start..position]);
    let mut attrs = Vec::new();
    let mut self_closing = false;
    loop {
        while position < bytes.len() && is_space(bytes[position]) {
            position += 1;
        }
        if position >= bytes.len() {
            break;
        }
        if bytes[position] == b'>' {
            position += 1;
            break;
        }
        if bytes[position] == b'/' {
            self_closing = true;
            position += 1;
            continue;
        }
        if attrs.len() >= MAX_ATTRS_PER_TAG {
            // Skip to the tag end without recording further attributes.
            while position < bytes.len() && bytes[position] != b'>' {
                position += 1;
            }
            if position < bytes.len() {
                position += 1;
            }
            break;
        }
        let attr_start = position;
        while position < bytes.len()
            && !is_space(bytes[position])
            && bytes[position] != b'='
            && bytes[position] != b'/'
            && bytes[position] != b'>'
        {
            position += 1;
        }
        let attr_name = lower_ascii(&bytes[attr_start..position]);
        while position < bytes.len() && is_space(bytes[position]) {
            position += 1;
        }
        let mut value = String::new();
        let mut value_dropped = false;
        if position < bytes.len() && bytes[position] == b'=' {
            position += 1;
            while position < bytes.len() && is_space(bytes[position]) {
                position += 1;
            }
            if position < bytes.len() && (bytes[position] == b'"' || bytes[position] == b'\'') {
                let quote = bytes[position];
                position += 1;
                let value_start = position;
                while position < bytes.len() && bytes[position] != quote {
                    position += 1;
                }
                let raw = &bytes[value_start..position.min(bytes.len())];
                if raw.len() > MAX_ATTR_VALUE_LEN {
                    value_dropped = true;
                } else {
                    value = decode_entities(&String::from_utf8_lossy(raw));
                }
                if position < bytes.len() {
                    position += 1;
                }
            } else {
                let value_start = position;
                while position < bytes.len()
                    && !is_space(bytes[position])
                    && bytes[position] != b'>'
                {
                    position += 1;
                }
                let raw = &bytes[value_start..position];
                if raw.len() > MAX_ATTR_VALUE_LEN {
                    value_dropped = true;
                } else {
                    value = decode_entities(&String::from_utf8_lossy(raw));
                }
            }
        }
        if !attr_name.is_empty() {
            attrs.push((attr_name, value, value_dropped));
        }
    }
    (is_end, name, attrs, self_closing, position)
}

fn attr_value<'a>(attrs: &'a [TagAttr], name: &[u8]) -> Option<&'a str> {
    attrs.iter().find_map(|(attr_name, value, dropped)| {
        (attr_name.as_slice() == name && !dropped).then_some(value.as_str())
    })
}

/// Skip a raw-text element body (`script`, `style`, …) to its matching close
/// tag. Returns the position after the close tag (or end of input).
fn skip_raw_text(bytes: &[u8], position: usize, name: &[u8]) -> usize {
    let mut index = position;
    while index < bytes.len() {
        if bytes[index] == b'<'
            && index + 2 + name.len() < bytes.len()
            && bytes[index + 1] == b'/'
            && lower_ascii(&bytes[index + 2..index + 2 + name.len()]) == name
        {
            let mut end = index + 2 + name.len();
            while end < bytes.len() && bytes[end] != b'>' {
                end += 1;
            }
            return (end + 1).min(bytes.len());
        }
        index += 1;
    }
    bytes.len()
}

fn push_capped(list: &mut Vec<RawRef>, truncated: &mut bool, cap: usize, value: String) {
    if list.len() >= cap {
        *truncated = true;
        return;
    }
    let value = value.trim().to_owned();
    if value.is_empty() {
        return;
    }
    if classify_reference(&value).is_none() {
        return;
    }
    list.push(RawRef {
        value,
        truncated_value: false,
    });
}

/// Extract references from an HTML document. Deterministic: document order
/// is preserved; caps only truncate tails.
pub fn extract_html_refs(html: &[u8]) -> HtmlRefs {
    let mut refs = HtmlRefs::default();
    let mut position = 0usize;
    let mut form_stack: Vec<FormStackEntry> = Vec::new();
    while position < html.len() {
        if html[position] != b'<' {
            position += 1;
            continue;
        }
        // Comments and declarations are skipped, never parsed.
        if html[position..].starts_with(b"<!--") {
            match html[position..]
                .windows(3)
                .position(|window| window == b"-->")
            {
                Some(index) => position += index + 3,
                None => break,
            }
            continue;
        }
        if html[position..].starts_with(b"<!") {
            while position < html.len() && html[position] != b'>' {
                position += 1;
            }
            position = (position + 1).min(html.len());
            continue;
        }
        let (is_end, name, attrs, _self_closing, next) = scan_tag(html, position + 1);
        position = next;
        if is_end {
            if name == b"form" {
                if let Some((action, method, inputs, inputs_truncated)) = form_stack.pop() {
                    if refs.forms.len() >= MAX_FORMS_PER_PAGE {
                        refs.truncated_forms = true;
                    } else {
                        refs.forms.push(FormRef {
                            action,
                            action_missing: false,
                            method,
                            inputs,
                            inputs_truncated,
                        });
                    }
                }
            }
            continue;
        }
        match name.as_slice() {
            b"a" => {
                if let Some(href) = attr_value(&attrs, b"href") {
                    push_capped(
                        &mut refs.links,
                        &mut refs.truncated_links,
                        MAX_LINKS_PER_PAGE,
                        href.to_owned(),
                    );
                }
            }
            b"form" => {
                let action = attr_value(&attrs, b"action").map(str::to_owned);
                let method = attr_value(&attrs, b"method")
                    .map(|value| value.to_ascii_uppercase())
                    .filter(|value| value == "GET" || value == "POST")
                    .unwrap_or_else(|| "GET".to_owned());
                form_stack.push((action, method, Vec::new(), false));
            }
            b"input" | b"select" | b"textarea" | b"button" => {
                if let Some((_, _, inputs, truncated)) = form_stack.last_mut() {
                    if inputs.len() >= MAX_INPUTS_PER_FORM {
                        *truncated = true;
                    } else {
                        let field_name = attr_value(&attrs, b"name").unwrap_or("").to_owned();
                        let field_type = if name.as_slice() == b"input" {
                            attr_value(&attrs, b"type")
                                .unwrap_or("text")
                                .to_ascii_lowercase()
                        } else {
                            String::from_utf8_lossy(&name).into_owned()
                        };
                        if !field_name.is_empty() {
                            inputs.push((field_name, field_type));
                        }
                    }
                }
                if name.as_slice() == b"textarea" {
                    position = skip_raw_text(html, position, b"textarea");
                }
            }
            b"script" => {
                if let Some(src) = attr_value(&attrs, b"src") {
                    push_capped(
                        &mut refs.scripts,
                        &mut refs.truncated_scripts,
                        MAX_SCRIPTS_PER_PAGE,
                        src.to_owned(),
                    );
                }
                position = skip_raw_text(html, position, b"script");
            }
            b"link" => {
                if let Some(href) = attr_value(&attrs, b"href") {
                    let rel = attr_value(&attrs, b"rel")
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if rel.split_whitespace().any(|token| token == "canonical")
                        && refs.canonical.is_none()
                    {
                        refs.canonical = Some(href.to_owned());
                    }
                    if rel.split_whitespace().any(|token| token == "stylesheet") {
                        push_capped(
                            &mut refs.stylesheets,
                            &mut refs.truncated_links,
                            MAX_LINKS_PER_PAGE,
                            href.to_owned(),
                        );
                    } else {
                        push_capped(
                            &mut refs.links,
                            &mut refs.truncated_links,
                            MAX_LINKS_PER_PAGE,
                            href.to_owned(),
                        );
                    }
                }
            }
            b"img" => {
                if let Some(src) = attr_value(&attrs, b"src") {
                    push_capped(
                        &mut refs.images,
                        &mut refs.truncated_images,
                        MAX_IMAGES_PER_PAGE,
                        src.to_owned(),
                    );
                }
            }
            b"iframe" | b"frame" => {
                if let Some(src) = attr_value(&attrs, b"src") {
                    push_capped(
                        &mut refs.links,
                        &mut refs.truncated_links,
                        MAX_LINKS_PER_PAGE,
                        src.to_owned(),
                    );
                }
            }
            b"base" => {
                if refs.base_href.is_none() {
                    if let Some(href) = attr_value(&attrs, b"href") {
                        refs.base_href = Some(href.to_owned());
                    }
                }
            }
            b"style" | b"title" => {
                position = skip_raw_text(html, position, &name);
            }
            _ => {}
        }
    }
    // Unclosed forms still count (malformed HTML must not lose evidence).
    for (action, method, inputs, inputs_truncated) in form_stack {
        if refs.forms.len() >= MAX_FORMS_PER_PAGE {
            refs.truncated_forms = true;
        } else {
            refs.forms.push(FormRef {
                action,
                action_missing: false,
                method,
                inputs,
                inputs_truncated,
            });
        }
    }
    refs
}

/// Classify a raw reference for crawling. Returns `None` for values that
/// must never become candidates (fragments, scripts-as-code, mail links,
/// data/blob URIs, empty strings). Everything else resolves against the
/// page URL by the caller.
pub fn classify_reference(raw: &str) -> Option<&str> {
    let value = raw.trim();
    if value.is_empty() || value.starts_with('#') {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    for scheme in [
        "javascript:",
        "data:",
        "mailto:",
        "tel:",
        "sms:",
        "ftp:",
        "file:",
        "about:",
        "blob:",
        "ws:",
        "wss:",
        "chrome:",
        "view-source:",
    ] {
        if lower.starts_with(scheme) {
            return None;
        }
    }
    Some(value)
}

/// Parsed robots.txt: conservative observations only. Disallow entries are
/// discovery inputs, never authorization of any kind.
#[derive(Debug, Clone, Default)]
pub struct RobotsData {
    pub allows: Vec<String>,
    pub disallows: Vec<String>,
    pub sitemaps: Vec<String>,
    pub lines_seen: usize,
    pub truncated: bool,
}

pub fn parse_robots_txt(text: &str) -> RobotsData {
    let mut data = RobotsData::default();
    // Truncate oversized input at a char boundary; the flag records it.
    let text = if text.len() > MAX_ROBOTS_BYTES {
        data.truncated = true;
        let mut end = MAX_ROBOTS_BYTES.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };
    for line in text.lines() {
        if data.lines_seen >= MAX_ROBOTS_LINES {
            data.truncated = true;
            break;
        }
        data.lines_seen += 1;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_owned();
        if value.is_empty() || value.len() > 2048 {
            continue;
        }
        match field.trim().to_ascii_lowercase().as_str() {
            "allow" => data.allows.push(value),
            "disallow" => data.disallows.push(value),
            "sitemap" => data.sitemaps.push(value),
            _ => {}
        }
    }
    data
}

/// Extract `<loc>` URLs from sitemap XML (urlset or index). Pure bounded
/// scanning: no XML library, no entity expansion attacks, no recursion.
/// Returns `(locations, truncated)` plus whether the document declares a
/// sitemap index.
pub fn extract_sitemap_locs(xml: &[u8]) -> (Vec<String>, bool, bool) {
    let mut locations = Vec::new();
    let mut truncated = false;
    let text = String::from_utf8_lossy(if xml.len() > 256 * 1024 {
        truncated = true;
        &xml[..256 * 1024]
    } else {
        xml
    });
    let lower = text.to_ascii_lowercase();
    let is_index = lower.contains("<sitemapindex");
    let bytes = text.as_bytes();
    let lower_bytes = lower.as_bytes();
    let mut position = 0usize;
    while position < lower_bytes.len() {
        if locations.len() >= MAX_SITEMAP_ENTRIES {
            truncated = true;
            break;
        }
        let Some(start) = find_tag_open(&lower_bytes[position..], b"loc") else {
            break;
        };
        let content_start = position + start;
        let Some(end) = find_tag_close(&lower_bytes[content_start..]) else {
            break;
        };
        let content_end = content_start + end;
        let mut value = bytes[content_start..content_end.min(bytes.len())].to_vec();
        // Strip a CDATA wrapper when present.
        if value.starts_with(b"<![CDATA[") {
            value.drain(..9);
            if let Some(stripped) = value
                .windows(3)
                .rposition(|window| window == b"]]>")
                .map(|index| value[..index].to_vec())
            {
                value = stripped;
            }
        }
        let value = String::from_utf8_lossy(&value).trim().to_owned();
        if !value.is_empty() && value.len() <= 2048 {
            locations.push(value);
        }
        position = content_end
            + "</loc>"
                .len()
                .min(lower_bytes.len().saturating_sub(content_end));
        if position <= content_start {
            break;
        }
    }
    (locations, is_index, truncated)
}

fn find_tag_open(haystack: &[u8], name: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    while index + 1 + name.len() < haystack.len() {
        if haystack[index] == b'<'
            && haystack[index + 1] != b'/'
            && haystack[index + 1] != b'!'
            && haystack[index + 1..index + 1 + name.len()].eq_ignore_ascii_case(name)
        {
            let after = index + 1 + name.len();
            if after < haystack.len()
                && (haystack[after] == b'>'
                    || haystack[after] == b' '
                    || haystack[after] == b'\t'
                    || haystack[after] == b'\n'
                    || haystack[after] == b'\r'
                    || haystack[after] == b'/')
            {
                // Return the position just after the opening tag's '>'.
                let mut end = after;
                while end < haystack.len() && haystack[end] != b'>' {
                    end += 1;
                }
                return Some(end.min(haystack.len() - 1) + 1);
            }
        }
        index += 1;
    }
    None
}

fn find_tag_close(haystack: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    while index + 6 <= haystack.len() {
        if haystack[index..index + 6].eq_ignore_ascii_case(b"</loc>") {
            return Some(index);
        }
        // A nested opening tag means malformed input; stop rather than bleed.
        if haystack[index] == b'<'
            && index + 4 < haystack.len()
            && haystack[index + 1] != b'/'
            && haystack[index + 1] != b'!'
        {
            return None;
        }
        index += 1;
    }
    None
}

/// Extract conservative URL/path candidates from JavaScript source WITHOUT
/// executing anything. Only string literals are inspected; template
/// `${...}` interpolations disqualify a literal; backslash-heavy literals
/// are skipped. Returns raw literal strings for the caller to resolve.
pub fn extract_js_urls(js: &[u8], cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(if js.len() > MAX_JS_BYTES {
        &js[..MAX_JS_BYTES]
    } else {
        js
    });
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut scanned = 0usize;
    while index < bytes.len() && scanned < MAX_JS_LITERALS.max(cap) {
        let quote = bytes[index];
        if quote != b'\'' && quote != b'"' && quote != b'`' {
            index += 1;
            continue;
        }
        scanned += 1;
        index += 1;
        let mut literal = String::new();
        let mut valid = true;
        let mut has_interpolation = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\\' {
                // Escaped char: keep tracking but mark regex-ish content as
                // untrustworthy for URL purposes.
                if index + 1 < bytes.len() && bytes[index + 1] == b'$' {
                    valid = false;
                }
                literal.push(byte as char);
                if index + 1 < bytes.len() {
                    literal.push(bytes[index + 1] as char);
                    index += 1;
                }
                index += 1;
                continue;
            }
            if quote == b'`' && byte == b'$' && index + 1 < bytes.len() && bytes[index + 1] == b'{'
            {
                has_interpolation = true;
                // Skip to the matching close brace.
                let mut depth = 0usize;
                while index < bytes.len() {
                    if bytes[index] == b'{' {
                        depth += 1;
                    } else if bytes[index] == b'}' {
                        depth -= 1;
                        if depth == 0 {
                            index += 1;
                            break;
                        }
                    }
                    index += 1;
                }
                continue;
            }
            if byte == quote {
                index += 1;
                break;
            }
            if byte == b'\n' && quote != b'`' {
                valid = false;
                break;
            }
            literal.push(byte as char);
            if literal.len() > MAX_LITERAL_LEN {
                valid = false;
                // Drain to the closing quote to keep scanning aligned.
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                if index < bytes.len() {
                    index += 1;
                }
                break;
            }
            index += 1;
        }
        if !valid || has_interpolation || out.len() >= cap {
            continue;
        }
        if let Some(candidate) = classify_js_literal(&literal) {
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    }
    out
}

/// Decide whether a JS string literal is an obvious URL/path reference.
/// Conservative: absolute http(s) URLs, root-relative paths, and relative
/// paths containing a slash or ending in a data extension. Everything else
/// (including bare words, CSS classes, and sentences) is ignored.
fn classify_js_literal(literal: &str) -> Option<String> {
    let value = literal.trim();
    if value.is_empty() || value.len() > MAX_LITERAL_LEN {
        return None;
    }
    if value.contains([' ', '\t', '\n', '\r', '<', '>', '"', '\'']) {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        if value.len() > 2048 {
            return None;
        }
        return Some(value.to_owned());
    }
    for scheme in [
        "javascript:",
        "data:",
        "mailto:",
        "tel:",
        "blob:",
        "ws:",
        "wss:",
        "ftp:",
        "file:",
        "about:",
        "#",
    ] {
        if lower.starts_with(scheme) {
            return None;
        }
    }
    if let Some(path) = value.strip_prefix('/') {
        if path.is_empty() {
            return None;
        }
        return Some(value.to_owned());
    }
    if value.contains('/') {
        return Some(value.to_owned());
    }
    for extension in [".js", ".json", ".xml", ".txt", ".map", ".css"] {
        if lower.ends_with(extension) {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_forms_scripts_and_base_resolve() {
        let html = br##"<html><head><base href="/root/"><link rel="canonical" href="https://EXAMPLE.test/canonical"></head><body><A HREF='Page2?a=1#frag'>x</A><a href=/rel/path>y</a><a href="https://other.test/abs">z</a><a href="#local">skip</a><a href="javascript:void(0)">skip</a><a href="mailto:a@b.c">skip</a><form action="/login" method="post"><input name="user" type="text"><input name="pw" type="password"></form><script src="/app.js"></script><script>var inline = "/must/not/appear";</script><img src="/i.png"><iframe src="/frame"></iframe></body></html>"##;
        let refs = extract_html_refs(html);
        let links: Vec<&str> = refs
            .links
            .iter()
            .map(|reference| reference.value.as_str())
            .collect();
        assert!(links.contains(&"Page2?a=1#frag"));
        assert!(links.contains(&"/rel/path"));
        assert!(links.contains(&"https://other.test/abs"));
        assert!(links.contains(&"/frame"));
        assert!(!links.iter().any(|link| link.contains("must/not/appear")));
        assert!(!links.iter().any(|link| link.starts_with('#')
            || link.starts_with("javascript:")
            || link.contains('@')));
        assert_eq!(refs.forms.len(), 1);
        assert_eq!(refs.forms[0].action.as_deref(), Some("/login"));
        assert_eq!(refs.forms[0].method, "POST");
        assert_eq!(refs.forms[0].inputs.len(), 2);
        assert_eq!(refs.scripts.len(), 1);
        assert_eq!(refs.images.len(), 1);
        assert_eq!(refs.base_href.as_deref(), Some("/root/"));
        assert_eq!(
            refs.canonical.as_deref(),
            Some("https://EXAMPLE.test/canonical")
        );
    }

    #[test]
    fn malformed_html_never_panics_and_still_extracts() {
        let html = b"<a href=/unclosed><a HREF=\"/second\"><!-- <a href=\"/commented\"> --><form><input name=x><img src>";
        let refs = extract_html_refs(html);
        let links: Vec<&str> = refs
            .links
            .iter()
            .map(|reference| reference.value.as_str())
            .collect();
        assert!(links.contains(&"/unclosed"));
        assert!(links.contains(&"/second"));
        assert!(!links.iter().any(|link| link.contains("commented")));
        assert_eq!(refs.forms.len(), 1);
        // Unterminated everything.
        let refs = extract_html_refs(b"<a href=\"/x");
        assert!(refs.links.is_empty() || refs.links.iter().all(|link| !link.value.is_empty()));
    }

    #[test]
    fn caps_truncate_tails_deterministically() {
        let mut html = b"<html><body>".to_vec();
        for index in 0..(MAX_LINKS_PER_PAGE + 25) {
            html.extend_from_slice(format!("<a href=\"/p{index}\">x</a>").as_bytes());
        }
        html.extend_from_slice(b"</body></html>");
        let refs = extract_html_refs(&html);
        assert_eq!(refs.links.len(), MAX_LINKS_PER_PAGE);
        assert!(refs.truncated_links);
        assert_eq!(refs.links[0].value, "/p0");
    }

    #[test]
    fn entities_decode_in_urls() {
        let refs = extract_html_refs(b"<a href=\"/a?a=1&amp;b=2\">x</a>");
        assert_eq!(refs.links[0].value, "/a?a=1&b=2");
    }

    #[test]
    fn robots_parses_fields_and_ignores_the_rest() {
        let data = parse_robots_txt(
            "# comment\nUser-agent: *\nAllow: /public\nDisallow: /admin\nDisallow: \nSitemap: https://example.test/sitemap.xml\nX-Custom: nope\n",
        );
        assert_eq!(data.allows, vec!["/public"]);
        assert_eq!(data.disallows, vec!["/admin"]);
        assert_eq!(data.sitemaps, vec!["https://example.test/sitemap.xml"]);
        assert!(!data.truncated);
    }

    #[test]
    fn sitemap_extracts_locs_and_detects_index() {
        let xml = b"<?xml version=\"1.0\"?><urlset xmlns=\"x\"><url><loc>https://example.test/a</loc></url><url><loc><![CDATA[https://example.test/b]]></loc></url></urlset>";
        let (locations, is_index, truncated) = extract_sitemap_locs(xml);
        assert_eq!(
            locations,
            vec!["https://example.test/a", "https://example.test/b"]
        );
        assert!(!is_index);
        assert!(!truncated);
        let index = b"<sitemapindex><sitemap><loc>https://example.test/s1.xml</loc></sitemap></sitemapindex>";
        let (locations, is_index, _) = extract_sitemap_locs(index);
        assert!(is_index);
        assert_eq!(locations, vec!["https://example.test/s1.xml"]);
        // Malformed input yields nothing, never panics.
        assert!(extract_sitemap_locs(b"<<<not xml").0.is_empty());
        assert!(
            extract_sitemap_locs(b"<loc>https://example.test/no-close")
                .0
                .is_empty()
        );
    }

    #[test]
    fn js_literals_classify_conservatively() {
        let js = br#"const a = "/api/v1/users"; fetch('https://cdn.test/lib.js'); var x = `prefix-${dynamic}/nope`; var y = "hello world"; var z = 'app.js'; var w = "data:text/plain;base64,xx";"#;
        let found = extract_js_urls(js, 50);
        assert!(found.contains(&"/api/v1/users".to_owned()));
        assert!(found.contains(&"https://cdn.test/lib.js".to_owned()));
        assert!(found.contains(&"app.js".to_owned()));
        assert!(!found.iter().any(|literal| literal.contains("nope")));
        assert!(!found.iter().any(|literal| literal.contains(' ')));
        assert!(!found.iter().any(|literal| literal.starts_with("data:")));
    }
}
