use crate::alerts;
use anyhow::Error;
use html_escape::decode_html_entities;
use html_parser::{Dom, Element, Node};
use tracing::{debug, trace};

#[derive(Debug)]
struct State {
    /// String containing the mrkdwn text.
    buf: String,
    /// Vec of element names from the top of the tree down to where we are.
    element_chain: Vec<String>,
}

impl State {
    fn new(capacity: usize) -> Self {
        State {
            buf: String::with_capacity(capacity),
            element_chain: Vec::new(),
        }
    }

    fn add_text(&mut self, string: &str) {
        self.buf.push_str(string)
    }
}

/// Given an event, extract the interesting portions and construct a message for Slack.
// XXX Should this return text in appropriate markup?  Should this return some sort of block kit
// type?
pub fn build_message(ev: &alerts::ServiceHealth) -> Result<String, Error> {
    // The communication property is (probably?) the thing most likely to have paragraph-style
    // descriptive text.  It may be in HTML.
    let buf = handle_html(&ev.properties.communication)?;

    debug!("Constructed message: {:?}", buf);
    Ok(buf)
}

fn handle_html(html: &str) -> Result<String, Error> {
    trace!("Parsing possible HTML: {:?}", html);
    let dom = Dom::parse(html)?;

    if !dom.errors.is_empty() {
        debug!("Non-fatal errors during parsing: {:?}", dom.errors);
    }

    let mut state = State::new(html.len());

    handle_elements(&mut state, &dom.children);

    Ok(state.buf)
}

fn handle_elements(state: &mut State, elements: &Vec<Node>) {
    for node in elements {
        match node {
            // XXX we actually need to convert <, >, and & back to HTML entities.
            Node::Text(text) => state.add_text(&decode_html_entities(&text)),
            Node::Element(element) => handle_element(state, &element),
            Node::Comment(_) => (),
        }
    }
}

fn handle_element(state: &mut State, element: &Element) {
    let tag = element.name.to_lowercase();
    // Adding the current element to the chain makes getting the parent more verbose, but there's
    // no good place to put it so that you can just use .last() without making it very repetitive.
    state.element_chain.push(tag.clone());

    // XXX a macro could make this nicer
    match tag.as_str() {
        "p" => handle_p(state, &element),
        "b" | "strong" => handle_b(state, &element),
        "i" | "em" | "u" => handle_i(state, &element),
        "a" => handle_a(state, &element),
        "ul" | "ol" => handle_ul(state, &element),
        "li" => handle_li(state, &element),
        // For elements we don't recognize or care about (say, <span>), just ignore them and handle
        // their children.
        // XXX We could have a debugging version that emitted representations of the start and end
        // tags.
        _ => handle_elements(state, &element.children),
    }

    state.element_chain.pop();
}

/// Grab all the text nodes beneath this element, ignoring all markup.
fn get_all_text(element: &Element) -> String {
    let mut buf = String::new();
    for node in &element.children {
        match node {
            Node::Text(text) => buf.push_str(&decode_html_entities(&text)),
            _ => (),
        }
    }
    buf
}

fn handle_p(state: &mut State, element: &Element) {
    state.add_text("\n");
    handle_elements(state, &element.children);
    // This is overkill if we have two adjacent p elements.  But otherwise we have to keep track of
    // that.  Ugh.
    state.add_text("\n");
}

// Obviously, this and similar tags will only work if there's some whitespace surrounding them.
fn handle_b(state: &mut State, element: &Element) {
    state.add_text("*");
    handle_elements(state, &element.children);
    state.add_text("*");
}

fn handle_i(state: &mut State, element: &Element) {
    state.add_text("_");
    handle_elements(state, &element.children);
    state.add_text("_");
}

fn handle_a(state: &mut State, element: &Element) {
    let link_text = get_all_text(&element);
    // Why are values in the attributes HashMap Option(String)?
    if let Some(Some(href)) = element.attributes.get("href") {
        state.add_text(&format!("<{href}|{link_text}>"));
    } else {
        state.add_text("[missing link] {link_text}");
    }
}

fn handle_ul(state: &mut State, element: &Element) {
    handle_elements(state, &element.children);
    state.add_text("\n");
}

fn handle_li(state: &mut State, element: &Element) {
    let parent = state.element_chain.iter().rev().nth(2);
    // We can't do proper lists unless we use the block kit; while "*" and "1." convert to bullets
    // and increasing numbers when typing into the app, they don't have that behavior here.  So we
    // use an explicit bullet (0x2022) for unordered lists.  We'd have to keep track of previous
    // siblings in order to manage the count, though.
    let marker = match parent {
        Some(tag) => match tag.as_str() {
            "ul" => "•",
            "ol" => "1.",
            _ => "•",
        },
        None => "•",
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
        <ol><li>one</li><li>two</li></ol>
        "#;

        let res = handle_html(html).unwrap();
        assert_eq!(res, "\n1. one\n1. two\n");
    }
}
