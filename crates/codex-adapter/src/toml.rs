use std::collections::{BTreeMap, BTreeSet};

use codex_application::{CompatibilityReason, LineEnding};

#[derive(Clone, Debug)]
pub struct Assignment {
    pub value: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug)]
pub struct ParsedToml {
    pub text: String,
    pub has_bom: bool,
    pub line_ending: LineEnding,
    pub assignments: BTreeMap<String, Assignment>,
}

fn bare(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn split_comment(line: &str) -> Result<(&str, usize), CompatibilityReason> {
    let bytes = line.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    for (i, b) in bytes.iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else if b == b'"' {
            quoted = true;
        } else if b == b'#' {
            return Ok((&line[..i], i));
        }
    }
    if quoted || escaped {
        return Err(CompatibilityReason::UnsupportedTomlSubset);
    }
    Ok((line, line.len()))
}

fn basic_string(value: &str) -> Result<String, CompatibilityReason> {
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return Err(CompatibilityReason::UnsupportedTomlSubset);
    }
    let inner = &value[1..value.len() - 1];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars
                .next()
                .ok_or(CompatibilityReason::UnsupportedTomlSubset)?
            {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                _ => return Err(CompatibilityReason::UnsupportedTomlSubset),
            }
        } else if ch == '"' || ch.is_control() {
            return Err(CompatibilityReason::UnsupportedTomlSubset);
        } else {
            out.push(ch)
        }
    }
    Ok(out)
}

fn validate_value(value: &str) -> Result<Option<String>, CompatibilityReason> {
    if value.starts_with('"') {
        return basic_string(value).map(Some);
    }
    if matches!(value, "true" | "false") {
        return Ok(None);
    }
    if value.parse::<i64>().is_ok() && !value.contains(['.', 'e', 'E']) {
        return Ok(None);
    }
    Err(CompatibilityReason::UnsupportedTomlSubset)
}

pub fn parse(bytes: &[u8]) -> Result<ParsedToml, CompatibilityReason> {
    let (has_bom, body) = if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        (true, &bytes[3..])
    } else {
        (false, bytes)
    };
    let text = std::str::from_utf8(body)
        .map_err(|_| CompatibilityReason::InvalidUtf8)?
        .to_owned();
    if text
        .as_bytes()
        .windows(1)
        .enumerate()
        .any(|(i, b)| b == b"\r" && text.as_bytes().get(i + 1) != Some(&b'\n'))
    {
        return Err(CompatibilityReason::MixedLineEndings);
    }
    let crlf = text.contains("\r\n");
    let lone_lf = text
        .as_bytes()
        .windows(1)
        .enumerate()
        .any(|(i, b)| b == b"\n" && (i == 0 || text.as_bytes()[i - 1] != b'\r'));
    if crlf && lone_lf {
        return Err(CompatibilityReason::MixedLineEndings);
    }
    let line_ending = if crlf {
        LineEnding::CrLf
    } else if lone_lf {
        LineEnding::Lf
    } else {
        LineEnding::None
    };
    let mut tables = BTreeSet::new();
    let mut assignments: BTreeMap<String, Assignment> = BTreeMap::new();
    let mut table = String::new();
    let mut offset = 0;
    for segment in text.split_inclusive('\n') {
        let line = segment
            .strip_suffix('\n')
            .unwrap_or(segment)
            .strip_suffix('\r')
            .unwrap_or(segment.strip_suffix('\n').unwrap_or(segment));
        if line.chars().any(|c| c.is_control() && c != '\t') {
            return Err(CompatibilityReason::UnsupportedTomlSubset);
        }
        let (code, _) = split_comment(line)?;
        let significant = code.trim_matches([' ', '\t']);
        if significant.is_empty() {
            offset += segment.len();
            continue;
        }
        if significant.starts_with("[[") {
            return Err(CompatibilityReason::UnsupportedTomlSubset);
        }
        if significant.starts_with('[') {
            if !significant.ends_with(']') {
                return Err(CompatibilityReason::UnsupportedTomlSubset);
            }
            let path = &significant[1..significant.len() - 1];
            if !path.split('.').all(bare) {
                return Err(CompatibilityReason::UnsupportedTomlSubset);
            }
            if path.starts_with("model_providers.") && path.split('.').count() != 2 {
                return Err(CompatibilityReason::UnsupportedTomlSubset);
            }
            if !tables.insert(path.to_owned()) {
                return Err(CompatibilityReason::DuplicateDefinition);
            }
            if assignments.keys().any(|key| {
                key == path
                    || key.starts_with(&format!("{path}."))
                    || path.starts_with(&format!("{key}."))
            }) {
                return Err(CompatibilityReason::DuplicateDefinition);
            }
            table = path.to_owned();
            offset += segment.len();
            continue;
        }
        let Some(equal) = significant.find('=') else {
            return Err(CompatibilityReason::UnsupportedTomlSubset);
        };
        let key = significant[..equal].trim_matches([' ', '\t']);
        if !bare(key) {
            return Err(CompatibilityReason::UnsupportedTomlSubset);
        }
        let raw_right = &significant[equal + 1..];
        let value = raw_right.trim_matches([' ', '\t']);
        let parsed = validate_value(value)?;
        let path = if table.is_empty() {
            key.to_owned()
        } else {
            format!("{table}.{key}")
        };
        if assignments.contains_key(&path)
            || tables
                .iter()
                .any(|t| t == &path || t.starts_with(&format!("{path}.")))
        {
            return Err(CompatibilityReason::DuplicateDefinition);
        }
        let line_code_start = line.find(significant).expect("trimmed substring");
        let value_in_significant = significant.find(value).expect("value substring");
        let start = offset + line_code_start + value_in_significant;
        let end = start + value.len();
        assignments.insert(
            path,
            Assignment {
                value: parsed.unwrap_or_else(|| value.to_owned()),
                start,
                end,
            },
        );
        offset += segment.len();
    }
    Ok(ParsedToml {
        text,
        has_bom,
        line_ending,
        assignments,
    })
}

pub fn encode_string(value: &str) -> String {
    let mut s = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            _ => s.push(c),
        }
    }
    s.push('"');
    s
}

pub fn replace_strings(
    parsed: &ParsedToml,
    replacements: &[(String, String)],
) -> Result<Vec<u8>, CompatibilityReason> {
    let mut ranges = Vec::new();
    for (path, value) in replacements {
        let a = parsed
            .assignments
            .get(path)
            .ok_or(CompatibilityReason::MissingManagedField)?;
        if !parsed.text[a.start..a.end].starts_with('"') {
            return Err(CompatibilityReason::UnsupportedTomlSubset);
        }
        ranges.push((a.start, a.end, encode_string(value)));
    }
    ranges.sort_by_key(|r| std::cmp::Reverse(r.0));
    let mut text = parsed.text.clone();
    for (start, end, value) in ranges {
        text.replace_range(start..end, &value)
    }
    let mut out = Vec::new();
    if parsed.has_bom {
        out.extend_from_slice(&[0xef, 0xbb, 0xbf])
    }
    out.extend_from_slice(text.as_bytes());
    Ok(out)
}
