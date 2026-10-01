//! A compact arena DOM.
//!
//! Nodes live in a `Vec` slab addressed by [`NodeId`] (u32 index) — cache
//! friendly and trivially cheap to clone. Document order is maintained by
//! first-child / next-sibling links, matching the classic browser design
//! (e.g. Servo's DOM) and giving O(1) traversal without parent-heavy
//! bookkeeping.

use std::fmt;

/// Handle to a node inside a [`Document`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct NodeId(pub(crate) u32);

impl NodeId {
    /// The null node handle.
    pub const NONE: NodeId = NodeId(u32::MAX);
}

/// The parsed document node kinds.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NodeKind {
    /// The document root.
    Document,
    /// An element with tag + attributes.
    Element(ElementData),
    /// Character data.
    Text(String),
    /// Comment (kept for fidelity, not rendered).
    Comment(String),
}

/// Element data: lowercase tag name plus attributes.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct ElementData {
    /// Lowercased tag name (`div`, `p`, `custom-hero`...).
    pub tag: String,
    /// Attributes in source order.
    pub attrs: Vec<(String, String)>,
}

impl ElementData {
    /// Attribute lookup, case-insensitive name match.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The `class` attribute split on whitespace.
    pub fn classes(&self) -> Vec<&str> {
        self.attr("class").map(|c| c.split_whitespace().collect()).unwrap_or_default()
    }

    /// The `id` attribute, when present.
    pub fn id(&self) -> Option<&str> {
        self.attr("id")
    }
}

/// A node entry in the arena.
#[derive(Debug, Clone)]
pub struct Node {
    /// Node kind/payload.
    pub kind: NodeKind,
    /// Parent node (NONE for the document).
    pub parent: NodeId,
    /// First child.
    pub first_child: NodeId,
    /// Next sibling.
    pub next_sibling: NodeId,
}

/// An arena-backed document.
#[derive(Debug, Clone, Default)]
pub struct Document {
    nodes: Vec<Node>,
}

impl Document {
    /// Create an empty document containing just the Document node.
    pub fn new() -> Document {
        let mut d = Document { nodes: Vec::with_capacity(128) };
        d.nodes.push(Node {
            kind: NodeKind::Document,
            parent: NodeId::NONE,
            first_child: NodeId::NONE,
            next_sibling: NodeId::NONE,
        });
        d
    }

    /// Number of live nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True when only the Document root exists.
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    /// Borrow a node.
    pub fn get(&self, id: NodeId) -> &Node {
        &self.nodes[id.0 as usize]
    }

    /// Mutably borrow a node.
    pub fn get_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id.0 as usize]
    }

    /// The document root node id.
    pub fn root(&self) -> NodeId {
        NodeId(0)
    }

    /// Create an unattached node; returns its id.
    pub fn create_node(&mut self, kind: NodeKind) -> NodeId {
        let id = NodeId(self.nodes.len() as u32);
        self.nodes.push(Node {
            kind,
            parent: NodeId::NONE,
            first_child: NodeId::NONE,
            next_sibling: NodeId::NONE,
        });
        id
    }

    /// Append `child` as the last child of `parent`.
    pub fn append(&mut self, parent: NodeId, child: NodeId) {
        let last = {
            let p = self.get(parent);
            if p.first_child == NodeId::NONE {
                None
            } else {
                Some(self.last_child_of(parent))
            }
        };
        self.get_mut(child).parent = parent;
        self.get_mut(child).next_sibling = NodeId::NONE;
        match last {
            None => {
                self.get_mut(parent).first_child = child;
            }
            Some(l) => {
                self.get_mut(l).next_sibling = child;
            }
        }
    }

    /// Append a fresh node with the given kind.
    pub fn append_new(&mut self, parent: NodeId, kind: NodeKind) -> NodeId {
        let id = self.create_node(kind);
        self.append(parent, id);
        id
    }

    /// Remove a node (and its subtree) from its parent.
    pub fn detach(&mut self, id: NodeId) {
        let parent = self.get(id).parent;
        if parent == NodeId::NONE {
            return;
        }
        let first = self.get(parent).first_child;
        if first == id {
            let next = self.get(id).next_sibling;
            self.get_mut(parent).first_child = next;
        } else {
            let mut cur = first;
            while cur != NodeId::NONE {
                let next = self.get(cur).next_sibling;
                if next == id {
                    let after = self.get(id).next_sibling;
                    self.get_mut(cur).next_sibling = after;
                    break;
                }
                cur = next;
            }
        }
        self.get_mut(id).parent = NodeId::NONE;
        self.get_mut(id).next_sibling = NodeId::NONE;
    }

    fn last_child_of(&self, parent: NodeId) -> NodeId {
        let mut cur = self.get(parent).first_child;
        let mut last = cur;
        while cur != NodeId::NONE {
            last = cur;
            cur = self.get(cur).next_sibling;
        }
        last
    }

    /// Iterate children of a node.
    pub fn children(&self, id: NodeId) -> Children<'_> {
        Children { doc: self, next: self.get(id).first_child }
    }

    /// Depth-first pre-order iterator over the whole tree.
    pub fn traverse(&self) -> Traverse<'_> {
        Traverse { doc: self, stack: vec![self.root()] }
    }

    /// Tag name of a node, if it is an element.
    pub fn tag_of(&self, id: NodeId) -> Option<&str> {
        match &self.get(id).kind {
            NodeKind::Element(e) => Some(&e.tag),
            _ => None,
        }
    }

    /// Element data of a node, if it is an element.
    pub fn element(&self, id: NodeId) -> Option<&ElementData> {
        match &self.get(id).kind {
            NodeKind::Element(e) => Some(e),
            _ => None,
        }
    }

    /// Text content of a node, if it is a text node.
    pub fn text_of(&self, id: NodeId) -> Option<&str> {
        match &self.get(id).kind {
            NodeKind::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Concatenated text content of a subtree (used for `<title>` etc.).
    pub fn inner_text(&self, id: NodeId) -> String {
        let mut out = String::new();
        for n in self.traverse_subtree(id) {
            if let Some(t) = self.text_of(n) {
                out.push_str(t);
            }
        }
        out
    }

    /// Pre-order traversal of a subtree rooted at `id`.
    pub fn traverse_subtree(&self, id: NodeId) -> Traverse<'_> {
        Traverse { doc: self, stack: vec![id] }
    }

    /// Find the first `<title>` text (for the tab title).
    pub fn title(&self) -> Option<String> {
        for n in self.traverse() {
            if let Some(e) = self.element(n) {
                if e.tag == "title" {
                    let t = self.inner_text(n);
                    if !t.trim().is_empty() {
                        return Some(t.trim().to_string());
                    }
                }
            }
        }
        None
    }

    /// Collect all element ids (helper for cosmetic filtering).
    pub fn all_elements(&self) -> Vec<NodeId> {
        self.traverse().filter(|&n| self.element(n).is_some()).collect()
    }
}

/// Iterator over a node's children.
pub struct Children<'a> {
    doc: &'a Document,
    next: NodeId,
}

impl<'a> Iterator for Children<'a> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        if self.next == NodeId::NONE {
            return None;
        }
        let cur = self.next;
        self.next = self.doc.get(cur).next_sibling;
        Some(cur)
    }
}

/// Pre-order depth-first traversal.
pub struct Traverse<'a> {
    doc: &'a Document,
    stack: Vec<NodeId>,
}

impl<'a> Iterator for Traverse<'a> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        let id = self.stack.pop()?;
        // push children in reverse so first child pops first
        let mut child = self.doc.get(id).first_child;
        let mut rev = Vec::new();
        while child != NodeId::NONE {
            rev.push(child);
            child = self.doc.get(child).next_sibling;
        }
        self.stack.extend(rev.into_iter().rev());
        Some(id)
    }
}

impl fmt::Display for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_node(f, self, self.root(), 0)
    }
}

fn write_node(f: &mut fmt::Formatter<'_>, doc: &Document, id: NodeId, depth: usize) -> fmt::Result {
    let indent = "  ".repeat(depth);
    match &doc.get(id).kind {
        NodeKind::Document => {
            for c in doc.children(id) {
                write_node(f, doc, c, depth)?;
            }
            Ok(())
        }
        NodeKind::Comment(c) => writeln!(f, "{indent}<!--{c}-->"),
        NodeKind::Text(t) => writeln!(f, "{indent}{t}"),
        NodeKind::Element(e) => {
            let attrs = e.attrs.iter().map(|(k, v)| format!(" {k}=\"{v}\"")).collect::<String>();
            writeln!(f, "{indent}<{}{attrs}>", e.tag)?;
            for c in doc.children(id) {
                write_node(f, doc, c, depth + 1)?;
            }
            writeln!(f, "{indent}</{}>", e.tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_tree() {
        let mut doc = Document::new();
        let html = doc.append_new(
            doc.root(),
            NodeKind::Element(ElementData { tag: "html".into(), attrs: vec![] }),
        );
        let body = doc
            .append_new(html, NodeKind::Element(ElementData { tag: "body".into(), attrs: vec![] }));
        doc.append_new(body, NodeKind::Text("Hello".into()));
        assert_eq!(doc.len(), 4);
        assert_eq!(doc.tag_of(body), Some("body"));
        assert_eq!(doc.inner_text(body), "Hello");
    }

    #[test]
    fn detach_removes_subtree() {
        let mut doc = Document::new();
        let div = doc.append_new(
            doc.root(),
            NodeKind::Element(ElementData { tag: "div".into(), attrs: vec![] }),
        );
        doc.append_new(div, NodeKind::Text("x".into()));
        doc.detach(div);
        assert_eq!(doc.children(doc.root()).count(), 0);
        // node data still exists but is unattached
        assert_eq!(doc.get(div).parent, NodeId::NONE);
    }

    #[test]
    fn traversal_is_preorder() {
        let mut doc = Document::new();
        let a = doc.append_new(
            doc.root(),
            NodeKind::Element(ElementData { tag: "a".into(), attrs: vec![] }),
        );
        let b = doc.append_new(
            doc.root(),
            NodeKind::Element(ElementData { tag: "b".into(), attrs: vec![] }),
        );
        doc.append_new(a, NodeKind::Text("1".into()));
        doc.append_new(b, NodeKind::Text("2".into()));
        let tags: Vec<String> =
            doc.traverse().filter_map(|n| doc.tag_of(n).map(|s| s.to_string())).collect();
        assert_eq!(tags, vec!["a", "b"]);
    }
}
