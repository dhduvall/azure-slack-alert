use crate::alerts;
use anyhow::Error;
use ego_tree::{iter::Children, NodeRef};
use html_escape::decode_html_entities;
use scraper::{Html, Node};
use tracing::{debug, instrument};

#[derive(Debug)]
struct State {
    /// String containing the mrkdwn text.
    buf: String,
}

impl State {
    fn new(capacity: usize) -> Self {
        State {
            buf: String::with_capacity(capacity),
        }
    }

    fn add_text(&mut self, string: &str) {
        self.buf.push_str(string)
    }
}

/// Given an event, extract the interesting portions and construct a message for Slack.
// XXX Should this return text in appropriate markup?  Should this return some sort of block kit
// type?
#[instrument]
pub fn build_message(al: &alerts::ActivityLog) -> Result<String, Error> {
    // The communication property is (probably?) the thing most likely to have paragraph-style
    // descriptive text.  It may be in HTML.
    let buf = match &al.data.context.activity_log {
        alerts::InnerActivityLog::ServiceHealth(ev) => handle_html(&ev.properties.communication)?,
        _ => {
            // We should never get here since the only caller calls us only on a ServiceHealth event.
            panic!("Unimplemented activity log type");
        }
    };

    Ok(buf)
}

#[instrument]
fn handle_html(html: &str) -> Result<String, Error> {
    let frag = Html::parse_fragment(html);

    if !frag.errors.is_empty() {
        debug!("Non-fatal errors during parsing: {:?}", frag.errors);
    }

    let mut state = State::new(html.len());

    handle_elements(&mut state, frag.tree.root().children());

    Ok(state.buf)
}

#[instrument]
fn handle_elements(state: &mut State, elements: Children<Node>) {
    for node in elements {
        match node.value() {
            // XXX we actually need to convert <, >, and & back to HTML entities.
            Node::Text(text) => {
                let s: &str = &*text;
                state.add_text(&decode_html_entities(&s))
            }
            Node::Element(_) => handle_element(state, node),
            Node::Document
            | Node::Fragment
            | Node::Doctype(_)
            | Node::Comment(_)
            | Node::ProcessingInstruction(_) => (),
        }
    }
}

#[instrument]
fn handle_element(state: &mut State, noderef: NodeRef<Node>) {
    // Our only caller has already checked that this is an element, so the unwrap() should never
    // panic.
    let element = noderef.value().as_element().unwrap();
    let tag = element.name().to_lowercase();

    // XXX a macro could make this nicer
    match tag.as_str() {
        "p" => handle_p(state, noderef),
        "br" => handle_br(state),
        "b" | "strong" => handle_b(state, noderef),
        "i" | "em" | "u" => handle_i(state, noderef),
        "code" | "tt" => handle_code(state, noderef),
        "strike" | "del" | "s" => handle_strike(state, noderef),
        "a" => handle_a(state, noderef),
        "ul" | "ol" => handle_ul(state, noderef),
        "li" => handle_li(state, noderef),
        // For elements we don't recognize or care about (say, <span>), just ignore them and handle
        // their children.
        // XXX We could have a debugging version that emitted representations of the start and end
        // tags.
        _ => handle_elements(state, noderef.children()),
    }
}

/// Grab all the text nodes beneath this element, ignoring all markup.
#[instrument]
fn get_all_text(noderef: NodeRef<Node>) -> String {
    let mut buf = String::new();
    for nr in noderef.descendants() {
        if let Some(text) = nr.value().as_text() {
            buf.push_str(text)
        }
    }
    buf
}

#[instrument]
fn handle_p(state: &mut State, noderef: NodeRef<Node>) {
    state.add_text("\n");
    handle_elements(state, noderef.children());
    // This is overkill if we have two adjacent p elements.  But otherwise we have to keep track of
    // that.  Ugh.
    state.add_text("\n");
}

#[instrument]
fn handle_br(state: &mut State) {
    state.add_text("\n");
}

#[instrument]
fn handle_b(state: &mut State, noderef: NodeRef<Node>) {
    handle_fontattr(state, noderef, "*");
}

#[instrument]
fn handle_i(state: &mut State, noderef: NodeRef<Node>) {
    handle_fontattr(state, noderef, "_");
}

#[instrument]
fn handle_code(state: &mut State, noderef: NodeRef<Node>) {
    handle_fontattr(state, noderef, "`");
}

#[instrument]
fn handle_strike(state: &mut State, noderef: NodeRef<Node>) {
    handle_fontattr(state, noderef, "~");
}

// These tags will only work if there's some whitespace surrounding them.  Since we can't count on
// the HTML to have them, we have to add spaces regardless.
#[instrument]
fn handle_fontattr(state: &mut State, noderef: NodeRef<Node>, c: &str) {
    // Slack doesn't understand markup in the middle of a word (*this is not bo*ld), so we add a
    // leading space if there isn't one at the end of the buffer already.  The pattern API which
    // would make that simplest isn't stable yet, so we just check for the most likely whitespace
    // characters: space and newline.
    if !state.buf.ends_with(" ") && !state.buf.ends_with("\n") {
        state.add_text(" ");
    }
    state.add_text(c);
    handle_elements(state, noderef.children());
    state.add_text(c);
    // To mirror the leading space we might have added, we could add a trailing space as well.
    // Note that Slack does know how to handle markup ending right before punctuation ( *this is
    // bold*), but we don't have a lookahead mechanism, so we'll punt.
}

#[instrument]
fn handle_a(state: &mut State, noderef: NodeRef<Node>) {
    // Some of the URLs we get are super long (2265 in front of me); might have to investigate a
    // URL shortener.
    // https://learn.microsoft.com/en-us/shows/azure-friday/azurlshortener-an-open-source-budget-friendly-url-shortener
    // What should we do when the <a> content has markup in it?  get_all_text() grabs just the
    // text.  Slack doesn't let you do markup inside the link text, but we could conceivably
    // extract all markup that applied to the entire contents and put it outside.
    let link_text = get_all_text(noderef);
    // Our only caller has already established this as being an element, so this should never
    // panic.
    let element = noderef.value().as_element().unwrap();
    if let Some(href) = element.attr("href") {
        state.add_text(&format!("<{href}|{link_text}>"));
    } else {
        state.add_text(&format!("[missing link] {link_text}"));
    }
}

#[instrument]
fn handle_ul(state: &mut State, noderef: NodeRef<Node>) {
    handle_elements(state, noderef.children());
    state.add_text("\n");
}

#[instrument]
fn handle_li(state: &mut State, noderef: NodeRef<Node>) {
    // Get the parent Element, if there is one.  If there isn't, this is simply None, which gets
    // the default of an unordered list.  That case is undefined in other ways, though.
    let parent = noderef.parent().and_then(|p| p.value().as_element());

    let marker = match parent {
        Some(tag) => match tag.name() {
            "ul" => "•".to_string(),
            "ol" => {
                let num = noderef.prev_siblings().count() + 1;
                format!("{num}.")
            }
            _ => "•".to_string(),
        },
        None => "•".to_string(),
    };
    state.add_text(&format!("\n{marker} "));
    handle_elements(state, noderef.children());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unordered_list() {
        let html = r#"
        <ul><li>one</li><li>two</li></ul>
        "#;

        let res = handle_html(html.trim()).unwrap();
        assert_eq!(res, "\n• one\n• two\n");
    }

    #[test]
    fn test_ordered_list() {
        let html = r#"
        <ol><li>one</li><li>two</li><li>three</li><li>four</li></ol>
        "#;

        let res = handle_html(html.trim()).unwrap();
        assert_eq!(res, "\n1. one\n2. two\n3. three\n4. four\n");
    }

    #[test]
    fn test_space_before_link() {
        let html = r#"
        Words. <a href="https://bit.ly">Link words.</a> More words.
        "#;

        let res = handle_html(html.trim()).unwrap();
        assert_eq!(res, "Words. <https://bit.ly|Link words.> More words.");
    }

    #[test]
    fn test_space_before_b() {
        let html = r#"
        Words. <b>Bold words.</b> More words.
        "#;

        let res = handle_html(html.trim()).unwrap();
        assert_eq!(res, "Words. *Bold words.* More words.");
    }

    #[test]
    fn test_newline_before_b() {
        let html = r#"
        Words.<p><b>Bold words.</b></p>More words.
        "#;

        let res = handle_html(html.trim()).unwrap();
        assert_eq!(res, "Words.\n*Bold words.*\nMore words.");
    }

    #[test]
    // Do lists work without a preceding paragraph break?
    fn test_list_after_text() {
        let html = r#"
        Words.<ul><li>one</li><li>two</li></ul>
        "#;

        let res = handle_html(html.trim()).unwrap();
        assert_eq!(res, "Words.\n• one\n• two\n");
    }

    #[test]
    fn test_list_before_text() {
        let html = r#"
        <ul><li>one</li><li>two</li></ul>Words.
        "#;

        let res = handle_html(html.trim()).unwrap();
        assert_eq!(res, "\n• one\n• two\nWords.");
    }

    #[test]
    fn test_missing_a_href() {
        let html = r#"blah <a>text</a> blah"#;
        let res = handle_html(html).unwrap();
        assert_eq!(res, "blah [missing link] text blah");
    }

    // This came out with the href printed instead of the <a> content.  Because the content is
    // missing entirely.  If we remove the <strong> from inside, it works.
    // doc ID 636022ba5b81183fc407fa00
    #[test]
    fn test_missing_a_content() {
        let html = r#"To avoid potential service disruptions, <strong>follow</strong> <a href="https://url.com"><strong>these instructions</strong></a> <strong>to check if your apps will be affected</strong> blah."#;
        let res = handle_html(html).unwrap();
        assert_eq!(
            res,
            "To avoid potential service disruptions, *follow* <https://url.com|these instructions> *to check if your apps will be affected* blah."
        );
    }

    // XXX need to check if "<strong>blah </strong><a href="blah">blah</a><strong> blah</strong>"
    // can be "*blah *<blah|blah>* blah*" or if it needs to be tweaked to "*blah* <blah|blah>
    // *blah*".

    #[test]
    fn test_get_all_text() {
        let html = r#"<strong>this is the text</strong>"#;
        let frag = Html::parse_fragment(html);
        let root = frag.tree.root();
        assert_eq!(root.children().count(), 1);
        let text = get_all_text(root.children().next().unwrap());
        assert_eq!(text, "this is the text");

        // Nested
        let html = r#"<em><strong>this is the text</strong></em>"#;
        let frag = Html::parse_fragment(html);
        let root = frag.tree.root();
        assert_eq!(root.children().count(), 1);
        let text = get_all_text(root.children().next().unwrap());
        assert_eq!(text, "this is the text");

        // Nested twice
        let html = r#"<em><strong><i>this is the text</i></strong></em>"#;
        let frag = Html::parse_fragment(html);
        let root = frag.tree.root();
        assert_eq!(root.children().count(), 1);
        let text = get_all_text(root.children().next().unwrap());
        assert_eq!(text, "this is the text");

        // Nested and mixed
        let html = r#"<em><strong><i>this is</i></strong> <b>the text</b></em>"#;
        let frag = Html::parse_fragment(html);
        let root = frag.tree.root();
        assert_eq!(root.children().count(), 1);
        let text = get_all_text(root.children().next().unwrap());
        assert_eq!(text, "this is the text");
    }
}
