//! HTML tree construction: tokens → [`Document`].
//!
//! A simplified but robust subset of the WHATWG insertion algorithm:
//! * implicit `<html><head><body>` scaffolding;
//! * void elements (`br`, `img`, `input`, `hr`, `meta`, `link`, ...) never
//!   get children;
//! * `<p>` auto-closing on block siblings;
//! * stray end tags are ignored;
//! * unclosed elements close implicitly at the end of input.
//!
//! The goal is a *stable, never-panicking* tree for arbitrary bytes, not
//! spec-exact error recovery — fuzzing drives the guarantees.

use crate::dom::{Document, ElementData, NodeId, NodeKind};
use crate::html_tokenizer::{tokenize, Token};

/// Elements that never have children.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Block-level elements that close an open `<p>`.
const BLOCK_ELEMENTS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "div",
    "dl",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "ul",
];

/// Elements whose end tag closes the whole stack down to them.
const SCOPE_ELEMENTS: &[&str] = &[
    "html", "body", "head", "table", "tbody", "thead", "tfoot", "tr", "td", "th", "ul", "ol", "li",
    "select", "option", "form", "div", "p",
];

/// Parse HTML into a DOM.
pub fn parse_html(input: &str) -> Document {
    let tokens = tokenize(input);
    build_tree(tokens)
}

/// Token stream → DOM.
pub fn build_tree(tokens: Vec<Token>) -> Document {
    let mut doc = Document::new();

    // Implicit scaffolding: <html><head></head><body></body></html>.
    let html = doc.append_new(
        doc.root(),
        NodeKind::Element(ElementData { tag: "html".into(), attrs: vec![] }),
    );
    let head =
        doc.append_new(html, NodeKind::Element(ElementData { tag: "head".into(), attrs: vec![] }));
    let body =
        doc.append_new(html, NodeKind::Element(ElementData { tag: "body".into(), attrs: vec![] }));

    let mut stack: Vec<NodeId> = vec![head];
    let mut mode = Mode::Head;
    // True while inserting the raw-text content of <script>/<style>/<title>/
    // <textarea>: character data belongs to the current node whatever the
    // surrounding insertion mode is.
    let mut in_raw_text = false;

    for tok in tokens {
        match tok {
            Token::Doctype(_) => { /* recorded, not materialized */ }
            Token::Comment(c) => {
                let parent = *stack.last().unwrap_or(&body);
                doc.append_new(parent, NodeKind::Comment(c));
            }
            Token::Text(t) => {
                let t = t.trim_matches('\r');
                if t.is_empty() {
                    continue;
                }
                if !in_raw_text && mode == Mode::Head {
                    // Whitespace-only text is dropped in head, kept in body.
                    if t.trim().is_empty() {
                        continue;
                    }
                    // Non-whitespace text before <body> switches to body mode
                    // (WHATWG "in head" character rule).
                    mode = Mode::Body;
                    stack = vec![body];
                }
                let parent = *stack.last().unwrap_or(&body);
                doc.append_new(parent, NodeKind::Text(t.to_string()));
            }
            Token::StartTag { name, attrs, self_closing } => {
                // Structural tags reuse the implicit nodes.
                match name.as_str() {
                    "html" => {
                        if let Some(el) = doc.element(html).cloned() {
                            let merged = ElementData { tag: el.tag, attrs };
                            doc.get_mut(html).kind = NodeKind::Element(merged);
                        }
                        continue;
                    }
                    "head" => {
                        mode = Mode::Head;
                        stack = vec![head];
                        continue;
                    }
                    "body" => {
                        if let Some(el) = doc.element(body).cloned() {
                            let merged = ElementData { tag: el.tag, attrs };
                            doc.get_mut(body).kind = NodeKind::Element(merged);
                        }
                        mode = Mode::Body;
                        stack = vec![body];
                        continue;
                    }
                    _ => {}
                }
                // First body-content tag transitions out of head.
                if mode == Mode::Head && !is_head_tag(&name) {
                    mode = Mode::Body;
                    stack = vec![body];
                }
                implicit_close_p(&mut stack, &doc, &name);
                let parent = *stack.last().unwrap_or(&body);
                let node = doc.append_new(
                    parent,
                    NodeKind::Element(ElementData { tag: name.clone(), attrs }),
                );
                let is_void = VOID_ELEMENTS.contains(&name.as_str());
                if !is_void && !self_closing {
                    if is_raw_text_element(&name) {
                        in_raw_text = true;
                    }
                    stack.push(node);
                }
            }
            Token::EndTag { name } => match name.as_str() {
                "html" => {}
                "head" => {
                    mode = Mode::Body;
                    stack = vec![body];
                }
                "body" => {}
                _ => {
                    if is_raw_text_element(&name) {
                        in_raw_text = false;
                    }
                    close_element(&mut stack, &doc, &name);
                }
            },
        }
    }
    doc
}

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Head,
    Body,
}

fn is_head_tag(tag: &str) -> bool {
    matches!(tag, "title" | "meta" | "link" | "style" | "script" | "base" | "noscript" | "template")
}

/// Elements whose content is raw text (tokenizer never tags inside them).
fn is_raw_text_element(tag: &str) -> bool {
    matches!(tag, "script" | "style" | "title" | "textarea")
}

/// Implicit `</p>`: a block-level start tag closes an open `<p>`.
fn implicit_close_p(stack: &mut Vec<NodeId>, doc: &Document, incoming: &str) {
    if !BLOCK_ELEMENTS.contains(&incoming) {
        return;
    }
    if let Some(pos) = stack.iter().rposition(|&n| doc.tag_of(n) == Some("p")) {
        // Only when no scope boundary sits between the <p> and the insertion
        // point, and the <p> is the innermost open element.
        let boundary = stack[pos..]
            .iter()
            .skip(1)
            .any(|&n| SCOPE_ELEMENTS.contains(&doc.tag_of(n).unwrap_or("")));
        if !boundary && pos + 1 == stack.len() {
            stack.truncate(pos);
        }
    }
}

/// Handle an end tag: pop the stack down to the matching element.
fn close_element(stack: &mut Vec<NodeId>, doc: &Document, name: &str) {
    if let Some(pos) = stack.iter().rposition(|&n| doc.tag_of(n) == Some(name)) {
        // Only allow closing elements that are "in scope" (top 1, or with
        // no scope boundary between) to bound pathological nesting.
        let boundary = stack[pos..]
            .iter()
            .skip(1)
            .any(|&n| SCOPE_ELEMENTS.contains(&doc.tag_of(n).unwrap_or("")));
        if !boundary || pos + 1 == stack.len() {
            stack.truncate(pos);
        }
    }
    // Stray end tags are ignored.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_scaffolding() {
        let doc = parse_html("<p>hello</p>");
        assert!(doc.tag_of(NodeId(1)) == Some("html"));
        let html = NodeId(1);
        let children: Vec<NodeId> = doc.children(html).collect();
        let tags: Vec<&str> = children.iter().filter_map(|&c| doc.tag_of(c)).collect();
        assert_eq!(tags, vec!["head", "body"]);
    }

    #[test]
    fn nested_structure() {
        let doc = parse_html("<div id=\"a\"><p>one</p><p>two</p></div>");
        let body = doc.traverse().find(|&n| doc.tag_of(n) == Some("body")).unwrap();
        let div = doc.children(body).next().unwrap();
        assert_eq!(doc.element(div).unwrap().attr("id"), Some("a"));
        let ps: Vec<NodeId> = doc.children(div).collect();
        assert_eq!(ps.len(), 2);
        assert_eq!(doc.inner_text(ps[0]), "one");
        assert_eq!(doc.inner_text(ps[1]), "two");
    }

    #[test]
    fn void_elements_have_no_children() {
        let doc = parse_html("<img src=\"x.png\">text after");
        let body = doc.traverse().find(|&n| doc.tag_of(n) == Some("body")).unwrap();
        let kids: Vec<NodeId> = doc.children(body).collect();
        assert_eq!(kids.len(), 2); // img + text
        assert!(doc.children(kids[0]).count() == 0);
    }

    #[test]
    fn implicit_p_closing() {
        let doc = parse_html("<p>one<p>two");
        let body = doc.traverse().find(|&n| doc.tag_of(n) == Some("body")).unwrap();
        let ps: Vec<NodeId> = doc.children(body).filter(|&c| doc.tag_of(c) == Some("p")).collect();
        assert_eq!(ps.len(), 2);
        assert_eq!(doc.inner_text(ps[0]), "one");
        assert_eq!(doc.inner_text(ps[1]), "two");
    }

    #[test]
    fn stray_end_tags_ignored() {
        let doc = parse_html("</div></p>hello");
        let body = doc.traverse().find(|&n| doc.tag_of(n) == Some("body")).unwrap();
        assert!(doc.inner_text(body).contains("hello"));
    }

    #[test]
    fn head_content_routed_to_head() {
        let doc = parse_html("<title>My page</title><meta charset=\"utf-8\"><body>hi</body>");
        let head = doc.traverse().find(|&n| doc.tag_of(n) == Some("head")).unwrap();
        assert!(doc.inner_text(head).contains("My page"));
        assert_eq!(doc.title(), Some("My page".to_string()));
        let metas: Vec<_> = doc.children(head).filter(|&c| doc.tag_of(c) == Some("meta")).collect();
        assert_eq!(metas.len(), 1);
    }

    #[test]
    fn unclosed_elements_close_at_eof() {
        // Deeply unclosed tags must not blow the stack or panic.
        let html = "<div>".repeat(200) + "text";
        let doc = parse_html(&html);
        assert!(doc.len() > 200);
    }

    #[test]
    fn tables_keep_basic_shape() {
        let doc = parse_html("<table><tr><td>a</td><td>b</td></tr></table>");
        let cells: Vec<_> = doc.traverse().filter(|&n| doc.tag_of(n) == Some("td")).collect();
        assert_eq!(cells.len(), 2);
    }
}
