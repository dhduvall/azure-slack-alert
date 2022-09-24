use crate::alerts;
use anyhow::Error;
use html_escape::decode_html_entities;
use html_parser::{Dom, Element, Node};
use tracing::{debug, instrument};

#[derive(Debug)]
struct State {
    /// String containing the mrkdwn text.
    buf: String,
    /// Vec of element names from the top of the tree down to where we are.  This includes the
    /// current element; the parent is the penultimate element in the Vec.
    element_chain: Vec<String>,
    /// How far in to an ordered list we are.
    ol_count: Option<usize>,
}

impl State {
    fn new(capacity: usize) -> Self {
        State {
            buf: String::with_capacity(capacity),
            element_chain: Vec::new(),
            ol_count: None,
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
    let dom = Dom::parse(html)?;

    // XXX Seems to be a bug in the parser, which strips whitespace before and after text nodes.
    // https://github.com/mathiversen/html-parser/issues/22

    if !dom.errors.is_empty() {
        debug!("Non-fatal errors during parsing: {:?}", dom.errors);
    }

    let mut state = State::new(html.len());

    handle_elements(&mut state, &dom.children);

    Ok(state.buf)
}

#[instrument]
fn handle_elements(state: &mut State, elements: &Vec<Node>) {
    for node in elements {
        match node {
            // XXX we actually need to convert <, >, and & back to HTML entities.
            Node::Text(text) => state.add_text(&decode_html_entities(&text)),
            Node::Element(element) => handle_element(state, element),
            Node::Comment(_) => (),
        }
    }
}

#[instrument]
fn handle_element(state: &mut State, element: &Element) {
    let tag = element.name.to_lowercase();
    // Adding the current element to the chain makes getting the parent more verbose, but there's
    // no good place to put it so that you can just use .last() without making it very repetitive.
    state.element_chain.push(tag.clone());

    // XXX a macro could make this nicer
    match tag.as_str() {
        "p" => handle_p(state, element),
        "b" | "strong" => handle_b(state, element),
        "i" | "em" | "u" => handle_i(state, element),
        "a" => handle_a(state, element),
        "ul" | "ol" => handle_ul(state, element),
        "li" => handle_li(state, element),
        // For elements we don't recognize or care about (say, <span>), just ignore them and handle
        // their children.
        // XXX We could have a debugging version that emitted representations of the start and end
        // tags.
        _ => handle_elements(state, &element.children),
    }

    state.element_chain.pop();
}

/// Grab all the text nodes beneath this element, ignoring all markup.
#[instrument]
fn get_all_text(element: &Element) -> String {
    let mut buf = String::new();
    for node in &element.children {
        if let Node::Text(text) = node {
            buf.push_str(&decode_html_entities(&text));
        }
    }
    buf
}

#[instrument]
fn handle_p(state: &mut State, element: &Element) {
    state.add_text("\n");
    handle_elements(state, &element.children);
    // This is overkill if we have two adjacent p elements.  But otherwise we have to keep track of
    // that.  Ugh.
    state.add_text("\n");
}

// Obviously, this and similar tags will only work if there's some whitespace surrounding them.
#[instrument]
fn handle_b(state: &mut State, element: &Element) {
    state.add_text("*");
    handle_elements(state, &element.children);
    state.add_text("*");
}

#[instrument]
fn handle_i(state: &mut State, element: &Element) {
    state.add_text("_");
    handle_elements(state, &element.children);
    state.add_text("_");
}

#[instrument]
fn handle_a(state: &mut State, element: &Element) {
    let link_text = get_all_text(element);
    // Why are values in the attributes HashMap Option(String)?
    if let Some(Some(href)) = element.attributes.get("href") {
        state.add_text(&format!("<{href}|{link_text}>"));
    } else {
        state.add_text("[missing link] {link_text}");
    }
}

#[instrument]
fn handle_ul(state: &mut State, element: &Element) {
    handle_elements(state, &element.children);
    state.ol_count = None;
    state.add_text("\n");
}

#[instrument]
fn handle_li(state: &mut State, element: &Element) {
    let parent = state.element_chain.iter().rev().nth(1); // nth() is zero-based

    let marker = match parent {
        Some(tag) => match tag.as_str() {
            "ul" => "•".to_string(),
            "ol" => {
                let num = state.ol_count.get_or_insert(0);
                *num += 1;
                format!("{num}.")
            }
            _ => "•".to_string(),
        },
        None => "•".to_string(),
    };
    state.add_text(&format!("\n{marker} "));
    handle_elements(state, &element.children);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unordered_list() {
        let html = r#"
        <ul><li>one</li><li>two</li></ul>
        "#;

        let res = handle_html(html).unwrap();
        assert_eq!(res, "\n• one\n• two\n");
    }

    #[test]
    fn test_ordered_list() {
        let html = r#"
        <ol><li>one</li><li>two</li><li>three</li><li>four</li></ol>
        "#;

        let res = handle_html(html).unwrap();
        assert_eq!(res, "\n1. one\n2. two\n3. three\n4. four\n");
    }

    #[test]
    // These two tests are failing because of the parser bug mentioned in handle_html().
    #[should_panic]
    fn test_space_before_link() {
        let html = r#"
        Words. <a href="https://bit.ly">Link words.</a> More words.
        "#;

        let res = handle_html(html).unwrap();
        assert_eq!(res, "Words. <https://bit.ly|Link words.> More words.");
    }

    #[test]
    #[should_panic]
    fn test_space_before_b() {
        let html = r#"
        Words. <b>Bold words.</b> More words.
        "#;

        let res = handle_html(html).unwrap();
        assert_eq!(res, "Words. *Bold words.* More words.");
    }

    #[test]
    // Do lists work without a preceding paragraph break?
    fn test_list_after_text() {
        let html = r#"
        Words.<ul><li>one</li><li>two</li></ul>
        "#;

        let res = handle_html(html).unwrap();
        assert_eq!(res, "Words.\n• one\n• two\n");
    }

    #[test]
    fn test_list_before_text() {
        let html = r#"
        <ul><li>one</li><li>two</li></ul>Words.
        "#;

        let res = handle_html(html).unwrap();
        assert_eq!(res, "\n• one\n• two\nWords.");
    }
}
