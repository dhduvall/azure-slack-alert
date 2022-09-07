use crate::alerts;
use anyhow::Error;
use html_escape::decode_html_entities;
use html_parser::{Dom, Element, Node};
use tracing::{debug, trace};

/// Given an event, extract the interesting portions and construct a message for Slack.
// XXX Should this return text in appropriate markup?  Should this return some sort of block kit
// type?
pub fn build_message(ev: &alerts::ServiceHealth) -> Result<String, Error> {
    // The communication property is (probably?) the thing most likely to have paragraph-style
    // descriptive text.  It may be in HTML.
    trace!("Parsing possible HTML: {:?}", &ev.properties.communication);
    let dom = Dom::parse(&ev.properties.communication)?;

    if !dom.errors.is_empty() {
        debug!("Non-fatal errors during parsing: {:?}", dom.errors);
    }

    let mut msg = String::with_capacity(ev.properties.communication.len());

    handle_elements(&mut msg, &dom.children);

    debug!("Constructed message: {msg:?}");
    Ok(msg)
}

fn handle_elements(msg: &mut String, elements: &Vec<Node>) {
    for node in elements {
        match node {
            // XXX we actually need to convert <, >, and & back to HTML entities.
            Node::Text(text) => msg.push_str(&decode_html_entities(&text)),
            Node::Element(element) => handle_element(msg, &element),
            Node::Comment(_) => (),
        }
    }
}

fn handle_element(msg: &mut String, element: &Element) {
    // XXX a macro could make this nicer
    match element.name.to_lowercase().as_str() {
        "p" => handle_p(msg, &element),
        "b" | "strong" => handle_b(msg, &element),
        "i" | "em" => handle_i(msg, &element),
        "a" => handle_a(msg, &element),
        // u, ul, ol, li
        // For elements we don't recognize or care about (say, <span>), just ignore them and handle
        // their children.
        // XXX We could have a debugging version that emitted representations of the start and end
        // tags.
        _ => handle_elements(msg, &element.children),
    }
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

fn handle_p(msg: &mut String, element: &Element) {
    msg.push_str("\n");
    handle_elements(msg, &element.children);
    // This is overkill if we have two adjacent p elements.  But otherwise we have to keep track of
    // that.  Ugh.
    msg.push_str("\n");
}

// Obviously, this and similar tags will only work if there's some whitespace surrounding them.
fn handle_b(msg: &mut String, element: &Element) {
    msg.push_str("*");
    handle_elements(msg, &element.children);
    msg.push_str("*");
}

fn handle_i(msg: &mut String, element: &Element) {
    msg.push_str("_");
    handle_elements(msg, &element.children);
    msg.push_str("_");
}

fn handle_a(msg: &mut String, element: &Element) {
    let link_text = get_all_text(&element);
    // Why are values in the attributes HashMap Option(String)?
    if let Some(Some(href)) = element.attributes.get("href") {
        msg.push_str(&format!("<{href}|{link_text}>"));
    } else {
        msg.push_str("[missing link] {link_text}");
    }
}
