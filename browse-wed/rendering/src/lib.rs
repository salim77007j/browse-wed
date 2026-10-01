//! # bw-render — the browse-wed rendering pipeline
//!
//! A deliberately minimal, memory-frugal rendering path:
//!
//! ```text
//! bytes → html_tokenizer → tree_builder → Document (arena DOM)
//!      → css::parse_stylesheet + css::cascade → ComputedStyle map
//!      → layout (block / flex, see css::FlexStyle) → paint (tiny-skia)
//! ```
//!
//! * [`html_tokenizer`] — WHATWG-style tokenizer that never errors out on
//!   malformed input; fuzz-targeted for the never-panic guarantee.
//! * [`tree_builder`] — token stream → arena DOM with the pragmatic subset of
//!   the WHATWG insertion algorithm (void elements, `<p>` auto-close,
//!   implicit scaffolding).
//! * [`dom`] — an arena DOM: nodes in a `Vec` slab addressed by [`NodeId`],
//!   first-child/next-sibling links, O(1) traversal, cheap clones.
//! * [`css`] — CSS parsing, cascade and inheritance for the property set the
//!   layout/paint pipeline consumes, plus a built-in user-agent sheet.
//! * [`fonts`] — system font discovery (`fontdb`), metrics and glyph
//!   rasterization (`swash`) into alpha masks.
//!
//! ## Design principles
//!
//! 1. **No panics on hostile input.** Every entry point is fuzzed; the
//!    tokenizer degrades garbage to character data, exactly like a browser.
//! 2. **Flat memory.** Arena DOM + slab allocation keeps per-node cost at
//!    ~a few dozen bytes with zero per-node heap allocations beyond text.
//! 3. **Synchronous layout thread.** The module set is designed to run inside
//!    a single page worker thread (see `bw-engine`), so no interior
//!    synchronization is needed here.

#![forbid(unsafe_code)]

pub mod css;
pub mod dom;
pub mod fonts;
pub mod html_tokenizer;
pub mod tree_builder;

pub use css::{cascade, parse_color, parse_stylesheet, ComputedStyle, Stylesheet};
pub use dom::{Document, ElementData, Node, NodeId, NodeKind};
pub use fonts::{FontKey, FontSystem, RasterGlyph, ScaledMetrics};
pub use html_tokenizer::{tokenize, Token};
pub use tree_builder::{build_tree, parse_html};
