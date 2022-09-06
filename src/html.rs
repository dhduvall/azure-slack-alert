use crate::alerts;
use anyhow::Error;
use html_escape::decode_html_entities;
use html_parser::{Dom, Node};
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

    for node in dom.children {
        match node {
            Node::Text(text) => msg += &decode_html_entities(&text),
            Node::Element(_) => (),
            Node::Comment(_) => (),
        }
    }

    debug!("Constructed message: {msg:?}");
    Ok(msg)
}
