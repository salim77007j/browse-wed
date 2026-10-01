//! HTML tokenizer — a pragmatic WHATWG-style state machine.
//!
//! Covers the states that matter for real-world pages: tag open/close,
//! attributes (quoted/unquoted), comments, doctype, CDATA-ish blocks and
//! raw-text elements (`script`/`style`/`textarea`/`title`). Malformed input
//! degrades to character data rather than erroring — browsers never reject
//! HTML, and neither do we. The tokenizer is fuzz-targeted (see
//! `tests/fuzz`).

/// A token emitted by the tokenizer.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// `<!DOCTYPE html ...>`
    Doctype(String),
    /// Start tag with name and attributes.
    StartTag {
        /// Lowercased tag name.
        name: String,
        /// Attributes; names lowercased.
        attrs: Vec<(String, String)>,
        /// Self-closing flag (`<br/>`).
        self_closing: bool,
    },
    /// End tag.
    EndTag {
        /// Lowercased tag name.
        name: String,
    },
    /// Character data run.
    Text(String),
    /// `<!-- ... -->`
    Comment(String),
}

/// Tokenize an HTML document into a token stream.
pub fn tokenize(input: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut chars = input.char_indices().peekable();
    let bytes = input;
    let mut text_start: Option<usize> = None;

    let flush_text = |out: &mut Vec<Token>, bytes: &str, start: Option<usize>, upto: usize| {
        if let Some(s) = start {
            if upto > s {
                let t = &bytes[s..upto];
                if !t.is_empty() {
                    out.push(Token::Text(t.to_string()));
                }
            }
        }
    };

    while let Some((i, ch)) = chars.next() {
        match ch {
            '<' => {
                // Decide whether this starts markup or is literal text.
                let next = chars.peek().map(|&(_, c)| c);
                let is_markup = match next {
                    Some('!') | Some('/') | Some('?') => true,
                    Some(c) => c.is_ascii_alphabetic(),
                    None => false,
                };
                if !is_markup {
                    if text_start.is_none() {
                        text_start = Some(i);
                    }
                    continue;
                }
                flush_text(&mut out, bytes, text_start.take(), i);
                // consume markup
                let (end, tok) = read_markup(bytes, i);
                if let Some(tok) = tok {
                    out.push(tok);
                }
                // advance iterator past consumed region
                while let Some(&(j, _)) = chars.peek() {
                    if j < end {
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Track raw-text elements: swallow content until the closer.
                let raw_name = out.last().and_then(|t| match t {
                    Token::StartTag { name, .. } => Some(name.clone()),
                    _ => None,
                });
                if let Some(name) = raw_name {
                    if is_raw_text(&name) {
                        let closer = format!("</{name}");
                        let rest = &bytes[end..];
                        if let Some(pos) = find_case_insensitive(rest, &closer) {
                            let content = &rest[..pos];
                            if !content.is_empty() {
                                out.push(Token::Text(content.to_string()));
                            }
                            // Consume through the `>` that terminates the end
                            // tag (it may carry attributes, e.g. `</title x>`).
                            let name_end = end + pos + closer.len();
                            let close_end = rest[name_end - end..]
                                .find('>')
                                .map(|g| name_end + g + 1)
                                .unwrap_or(name_end);
                            out.push(Token::EndTag { name });
                            while let Some(&(j, _)) = chars.peek() {
                                if j < close_end {
                                    chars.next();
                                } else {
                                    break;
                                }
                            }
                        } else {
                            if !rest.is_empty() {
                                out.push(Token::Text(rest.to_string()));
                            }
                            out.push(Token::EndTag { name });
                            break;
                        }
                    }
                }
            }
            _ => {
                if text_start.is_none() {
                    text_start = Some(i);
                }
            }
        }
    }
    flush_text(&mut out, bytes, text_start, bytes.len());
    out
}

fn is_raw_text(tag: &str) -> bool {
    matches!(tag, "script" | "style" | "textarea" | "title" | "xmp" | "plaintext")
}

/// Read one markup construct starting at `<`. Returns (end_offset, token).
fn read_markup(bytes: &str, start: usize) -> (usize, Option<Token>) {
    let rest = &bytes[start..];
    let second = rest.chars().nth(1);

    let Some(second) = second else {
        return (start + 1, None);
    };

    if second == '!' {
        // comment / doctype
        if rest[2..].starts_with("--") {
            if let Some(end) = rest.find("-->") {
                let content = &rest[4..end];
                return (start + end + 3, Some(Token::Comment(content.to_string())));
            }
            return (bytes.len(), Some(Token::Comment(rest[4..].to_string())));
        }
        if rest[2..].starts_with("DOCTYPE") || rest[2..].starts_with("doctype") {
            if let Some(end) = rest.find('>') {
                let content = &rest[2..end];
                return (start + end + 1, Some(Token::Doctype(content.to_string())));
            }
            return (bytes.len(), Some(Token::Doctype(rest[2..].to_string())));
        }
        // bogus comment: `<!...>` until '>'
        if let Some(end) = rest.find('>') {
            return (start + end + 1, Some(Token::Comment(rest[2..end].to_string())));
        }
        return (bytes.len(), Some(Token::Comment(rest[2..].to_string())));
    }

    if second == '?' {
        // processing instruction → comment until '>'
        if let Some(end) = rest.find('>') {
            return (start + end + 1, Some(Token::Comment(rest[1..end].to_string())));
        }
        return (bytes.len(), Some(Token::Comment(rest[1..].to_string())));
    }

    if second == '/' {
        // end tag
        let name_start = start + 2;
        let mut i = name_start;
        let mut name = String::new();
        for c in bytes[name_start..].chars() {
            if c == '>' || c.is_whitespace() {
                break;
            }
            name.push(c.to_ascii_lowercase());
            i += c.len_utf8();
        }
        // skip to '>'
        let mut end = i;
        for c in bytes[end..].chars() {
            end += c.len_utf8();
            if c == '>' {
                break;
            }
        }
        return (end, Some(Token::EndTag { name }));
    }

    if second.is_ascii_alphabetic() {
        // start tag: read name
        let mut i = start + 1;
        let mut name = String::new();
        for c in bytes[i..].chars() {
            if c == '>' || c == '/' || c.is_whitespace() {
                break;
            }
            name.push(c.to_ascii_lowercase());
            i += c.len_utf8();
        }
        // read attributes
        let mut attrs: Vec<(String, String)> = Vec::new();
        let mut self_closing = false;
        loop {
            // skip whitespace
            while i < bytes.len() {
                let c = bytes[i..].chars().next().unwrap();
                if c.is_whitespace() {
                    i += c.len_utf8();
                } else {
                    break;
                }
            }
            if i >= bytes.len() {
                return (bytes.len(), None);
            }
            let c = bytes[i..].chars().next().unwrap();
            if c == '>' {
                return (i + 1, Some(Token::StartTag { name, attrs, self_closing }));
            }
            if c == '/' {
                self_closing = true;
                i += 1;
                continue;
            }
            // attribute name
            let mut an = String::new();
            while i < bytes.len() {
                let c = bytes[i..].chars().next().unwrap();
                if c == '=' || c == '>' || c.is_whitespace() || c == '/' {
                    break;
                }
                an.push(c.to_ascii_lowercase());
                i += c.len_utf8();
            }
            // skip ws, then optional = value
            let mut j = i;
            while j < bytes.len() {
                let c = bytes[j..].chars().next().unwrap();
                if c.is_whitespace() {
                    j += c.len_utf8();
                } else {
                    break;
                }
            }
            let mut value = String::new();
            if j < bytes.len() && bytes[j..].starts_with('=') {
                j += 1;
                while j < bytes.len() {
                    let c = bytes[j..].chars().next().unwrap();
                    if !c.is_whitespace() {
                        break;
                    }
                    j += c.len_utf8();
                }
                if j < bytes.len() {
                    let q = bytes[j..].chars().next().unwrap();
                    if q == '"' || q == '\'' {
                        j += 1;
                        let vstart = j;
                        while j < bytes.len() {
                            let c = bytes[j..].chars().next().unwrap();
                            if c == q {
                                break;
                            }
                            j += c.len_utf8();
                        }
                        value = bytes[vstart..j].to_string();
                        if j < bytes.len() {
                            j += 1; // closing quote
                        }
                    } else {
                        let vstart = j;
                        while j < bytes.len() {
                            let c = bytes[j..].chars().next().unwrap();
                            if c.is_whitespace() || c == '>' {
                                break;
                            }
                            j += c.len_utf8();
                        }
                        value = bytes[vstart..j].to_string();
                    }
                }
                i = j;
            } else {
                // valueless attribute
                i = j;
            }
            if !an.is_empty() && !attrs.iter().any(|(k, _)| *k == an) {
                attrs.push((an, value));
            }
        }
    }

    // lone '<' — treat as text
    (start + 1, None)
}

/// Case-insensitive substring search (for `</script>` detection).
fn find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    for i in 0..=h.len() - n.len() {
        if h[i..i + n.len()]
            .iter()
            .zip(n.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_document() {
        let toks = tokenize("<!DOCTYPE html><html><head><title>T</title></head><body><p class=\"x\">Hi</p></body></html>");
        assert!(matches!(toks[0], Token::Doctype(_)));
        assert_eq!(
            toks.iter().filter(|t| matches!(t, Token::StartTag { .. })).count(),
            5
        );
        let p = toks.iter().find_map(|t| match t {
            Token::StartTag { name, attrs, .. } if name == "p" => Some(attrs.clone()),
            _ => None,
        });
        assert_eq!(p, Some(vec![("class".to_string(), "x".to_string())]));
    }

    #[test]
    fn raw_text_script() {
        let toks = tokenize("<body><script>if (a < b) { f(); }</script></body>");
        let texts: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert!(texts.contains(&"if (a < b) { f(); }"), "texts: {texts:?}");
    }

    #[test]
    fn unquoted_and_valueless_attrs() {
        let toks = tokenize("<input type=checkbox disabled>");
        match &toks[0] {
            Token::StartTag { attrs, .. } => {
                assert_eq!(
                    attrs,
                    &vec![
                        ("type".to_string(), "checkbox".to_string()),
                        ("disabled".to_string(), String::new())
                    ]
                );
            }
            _ => panic!("expected start tag"),
        }
    }

    #[test]
    fn single_quoted_attrs() {
        let toks = tokenize("<div id='main' data-x='a b'></div>");
        match &toks[0] {
            Token::StartTag { attrs, .. } => {
                assert_eq!(attrs[0], ("id".to_string(), "main".to_string()));
                assert_eq!(attrs[1], ("data-x".to_string(), "a b".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn malformed_html_is_text() {
        let toks = tokenize("a < b and 5 > 3");
        assert!(!toks.is_empty());
        match &toks[0] {
            Token::Text(t) => assert!(t.contains("a < b"), "got: {t:?}"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn self_closing_tags() {
        let toks = tokenize("<br/><img src=\"x.png\" />");
        match &toks[0] {
            Token::StartTag { name, self_closing, .. } => {
                assert_eq!(name, "br");
                assert!(self_closing);
            }
            _ => panic!(),
        }
        match &toks[1] {
            Token::StartTag { name, self_closing, .. } => {
                assert_eq!(name, "img");
                assert!(self_closing);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn comments_and_bogus() {
        let toks = tokenize("<!-- hello --><!bogus><?php echo 1; ?>");
        // Per WHATWG bogus-comment state the `?` is part of the data —
        // exactly what Chrome/Firefox emit for `<?php ... ?>` in HTML.
        assert_eq!(
            toks,
            vec![
                Token::Comment(" hello ".into()),
                Token::Comment("bogus".into()),
                Token::Comment("?php echo 1; ?".into()),
            ]
        );
    }

    #[test]
    fn unclosed_tags_tolerated() {
        let toks = tokenize("<div><p>never closed");
        assert_eq!(toks.len(), 3); // 2 start tags + 1 text run
        assert!(matches!(&toks[2], Token::Text(t) if t == "never closed"));
    }

    #[test]
    fn never_loses_text_tail() {
        let toks = tokenize("<p>hello");
        assert!(matches!(toks.last(), Some(Token::Text(t)) if t == "hello"));
    }
}
