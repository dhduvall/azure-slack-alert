use anyhow::Context;
use axum::{
    extract::{rejection::JsonRejection, Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use axum_macros::debug_handler;
use azure_identity::{AzureCliCredential, DefaultAzureCredential, DefaultAzureCredentialEnum};
use azure_security_keyvault::SecretClient;
use mongodb::{options::ClientOptions, results::InsertOneResult, Client};
use slack_morphism::prelude::*;
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{debug, error, info, instrument, trace, warn};
use uname::uname;

pub mod alerts;
pub mod html;

enum EnvDefaults {
    CosmosCollectionName,
    CosmosConnectionStringKey,
    CosmosDBName,
    FunctionsCustomHandlerPort,
    KeyVaultName,
    SlackAPIKeyName,
}

fn env_default(var: EnvDefaults) -> String {
    let kv_default = match var {
        EnvDefaults::CosmosConnectionStringKey => (
            "COSMOS_CONNECTION_STRING_KEY",
            "cosmos-mongodb-primary-connection-string",
        ),
        EnvDefaults::CosmosDBName => ("COSMOS_DB_NAME", "service-health-alerts"),
        EnvDefaults::CosmosCollectionName => ("COSMOS_COLLECTION_NAME", "alerts"),
        EnvDefaults::FunctionsCustomHandlerPort => ("FUNCTIONS_CUSTOMHANDLER_PORT", "3000"),
        EnvDefaults::KeyVaultName => ("KEYVAULT_NAME", "coros-svc-health-alert"),
        EnvDefaults::SlackAPIKeyName => ("SLACK_API_KEY_NAME", "slack-bot-oauth-token"),
    };

    if let Ok(value) = env::var(kv_default.0) {
        value
    } else {
        kv_default.1.to_string()
    }
}

fn init_logger() {
    if atty::is(atty::Stream::Stdin) {
        tracing_subscriber::fmt::init();
    } else {
        // XXX Can we log to datadog, too?  The Azure console is awful.
        // This duplicates the code in tracing_subscriber::fmt::try_init().  See
        // https://github.com/tokio-rs/tracing/issues/1329 and
        // https://github.com/tokio-rs/tracing/issues/2217
        use tracing_core::metadata::LevelFilter;
        use tracing_subscriber::{fmt::Subscriber, util::SubscriberInitExt};
        let builder = Subscriber::builder()
            .with_max_level(LevelFilter::TRACE)
            .json();

        let subscriber = builder.finish();
        let subscriber = {
            use std::str::FromStr;
            use tracing_subscriber::{filter::Targets, layer::SubscriberExt};

            let targets = match env::var("RUST_LOG") {
                Ok(var) => Targets::from_str(&var)
                    .map_err(|e| {
                        eprintln!("Ignoring `RUST_LOG={:?}`: {}", var, e);
                    })
                    .unwrap_or_default(),
                Err(env::VarError::NotPresent) => {
                    Targets::new().with_default(Subscriber::DEFAULT_MAX_LEVEL)
                }
                Err(e) => {
                    eprintln!("Ignoring `RUST_LOG`: {}", e);
                    Targets::new().with_default(Subscriber::DEFAULT_MAX_LEVEL)
                }
            };
            subscriber.with(targets)
        };

        subscriber.init();
    }
}

#[tokio::main]
#[instrument]
async fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() > 1 {
        debug_parse_file(&args[1]);
        return;
    }

    init_logger();

    let app = Router::new()
        .route("/api/ServiceHealthAlert", get(do_get).post(do_post))
        // When deployed, the function invocation URL seems to get lower-cased:
        // https://github.com/MicrosoftDocs/azure-docs/issues/98464
        .route("/api/servicehealthalert", get(do_get).post(do_post))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let port: u16 = env_default(EnvDefaults::FunctionsCustomHandlerPort)
        .parse()
        .expect("Custom Handler port in $FUNCTIONS_CUSTOMHANDLER_PORT is not a number!");

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn debug_parse_file(filename: &String) {
    let path = std::path::Path::new(&filename);
    let f = std::fs::File::open(path).unwrap();

    let alert: alerts::ActivityLog = serde_json::from_reader(f).unwrap();
    let md_text = match &alert.data.context.activity_log {
        alerts::InnerActivityLog::ServiceHealth(sh_alert) => {
            print!("HTML input\n{}\n", &sh_alert.properties.communication);
            html::build_message(&alert)
        }
        _ => todo!(),
    }
    .unwrap();
    println!("\nText has {} characters", md_text.len());
    println!("\n{}", md_text);

    let mut blocks: Vec<SlackBlock> = vec![];
    // slack_blocks![
    //     some_into(SlackHeaderBlock::new(pt!(title))),
    //     optionally_into(metadata_fields.is_some() => metadata_fields.unwrap()),
    //     some_into(SlackDividerBlock::new())
    // ];

    blocks.extend(
        split_text(&md_text, 3000)
            .into_iter()
            .map(|block_text| SlackSectionBlock::new().with_text(md!(block_text)).into()),
    );
    println!("\n{:#?}", blocks);
}

#[instrument]
async fn do_get(params: Option<Query<HashMap<String, String>>>) -> String {
    let Query(params) = params.unwrap_or_default();
    match params.get("name") {
        Some(name) => format!("Hello, {name}. This HTTP-triggered function executed successfully."),
        None => "This HTTP-triggered function executed successfully. Pass a name in the query string for a personalized response.".into(),
    }
}

/// This decodes the input as a JSON document representing an activity log and passes it on if that
/// succeeds.
// All the return types must be the same.  If that's not appropriate, we can call .into_response():
// https://docs.rs/axum/0.5.15/axum/response/index.html#returning-different-response-types
#[instrument(skip(v))]
#[debug_handler]
async fn do_post(
    v: Result<Json<alerts::ActivityLog>, JsonRejection>,
    params: Option<Query<HashMap<String, String>>>,
) -> impl IntoResponse {
    let Query(params) = params.unwrap_or_default();
    if let Some(collection_name) = params.get("collection") {
        env::set_var("COSMOS_COLLECTION_NAME", collection_name);
    }
    if let Some(target) = params.get("target") {
        env::set_var("SLACK_TARGET_USER", target);
    }

    let resp = match v.http_err_map(StatusCode::BAD_REQUEST, "rejected JSON input".to_string()) {
        Ok(v) => handle_activity_log(&v).await,
        Err(e) => Err(e),
    };

    match resp {
        Ok(r) => r.into_response(),
        Err(e) => {
            // Log the full error, but return only the status code.
            // XXX stuffing all the error data into a string is lazy.  We probably want to expand
            // it using tracing-core's experimental support for valuable.  It's really the only way
            // to get nested structure.  At least this string contains all the nested error data.
            error!("#?: {e:#?}");
            error!("?: {e:?}");
            Err::<(StatusCode, String), _>(e.status_code).into_response()
        }
    }
}

#[derive(Debug)]
struct HTTPError {
    // source: Option<Box<dyn std::error::Error + Send + 'static>>,
    status_code: StatusCode,
    log_msg: String,
}

// This type exists solely to be able to implement external traits on what might otherwise just be
// a tuple.
impl HTTPError {
    fn new<S: Into<String>>(status_code: StatusCode, log_msg: S) -> Self {
        let log_msg = log_msg.into();
        Self {
            // source: None,
            status_code,
            log_msg,
        }
    }

    /*
    fn wrap<E: std::error::Error + std::marker::Send + 'static, S: Into<String>>(
        source: E,
        status_code: StatusCode,
        log_msg: S,
    ) -> Self {
        let log_msg = log_msg.into();
        Self {
            source: Some(Box::new(source)),
            status_code,
            log_msg,
        }
    }
    */
}

impl axum_core::response::IntoResponse for HTTPError {
    fn into_response(self) -> axum::response::Response {
        let mut res = self.log_msg.into_response();
        *res.status_mut() = self.status_code;
        res
    }
}

// Needed for it to be an anyhow error.
impl std::fmt::Display for HTTPError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error {}: {}", self.status_code, self.log_msg)
    }
}

/*
impl std::error::Error for HTTPError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.source {
            None => None,
            Some(x) => Some(&*x),
        }
    }
}
*/

// XXX Can we maybe create our own trait that lets us convert anyhow::Error into an axum Response?

trait WrapErr<T> {
    fn http_err_map(self, code: StatusCode, msg: String) -> Result<T, HTTPError>;
}

impl<T, E> WrapErr<T> for Result<T, E>
where
    E: std::fmt::Debug,
{
    // XXX Want to be able to take Into<String>
    fn http_err_map(self, code: StatusCode, msg: String) -> Result<T, HTTPError> {
        match self {
            Ok(v) => Ok(v),
            // It would be better to embed the error directly, rather than in the message string.
            Err(e) => Err(HTTPError::new(code, format!("{msg}: {e:#?}"))),
        }
    }
}

// Error handling
// - Whatever is called by the router needs to return an axum Response.  Currently, this is
//   do_post().
// - The Response must include a status code and something that goes into the body.
// - The status code is determined by the root cause error (probably?); the body is probably set in
//   the same place.
// - Errors propagating back down the stack must thus carry the status code and body.
// - Errors propagating down the stack must chain
// - Errors must be logged with full context; this probably means that we log as close to the
//   bottom of the stack as we can.
// - But at the bottom of the stack we have no idea what the error message should be, if there is
//   one.  Maybe the outermost error has that information?  Or maybe that text has to be carried
//   down as well.
// - None of the functions in this module should really return anything.
// - All HTTP-related decisions (like what failures are considered errors, and what HTTP status
//   code they should be assigned) are being made in this module.
//
// I think we need a custom Error type that contains the status code and body (and maybe an
// optional string useful to have in the logs).  It will need to implement whatever is necessary to
// implement std::error::Error.
//
// Or it can just implement anyhow::Context (which basically means Display), and we chain with
// .with_context().
//
// What does success look like here?  Just ()?  We shouldn't need anything other than 200, but if
// we needed anything else, we'd need to pass back a status code and body message.
//
// Could do something like
// https://rust-on-nails.com/docs/full-stack-web/web-server/ (custom error, impl Into from various
// other errors, impl IntoResponse)
// https://github.com/ndelvalle/rustapi/tree/master/src (enum, with thiserror)
// rgit has a custom error that's a tuple struct around an anyhow Error, impling From that as well
// as IntoResponse.
// notify-run has a custom Result type that uses StatusCode as its error variant; it implements a
// custom trait that logs the error and returns the appropriate StatusCode as an error variant.

#[instrument(skip(al))]
// #[debug_handler]
async fn handle_activity_log(al: &alerts::ActivityLog) -> Result<(StatusCode, String), HTTPError> {
    let doc_id = match save_doc(al).await {
        Ok(v) => {
            info!("saved activity log with document ID {}", v.inserted_id);
            v.inserted_id.as_object_id().map(|oid| oid.to_hex())
        }
        Err(e) => {
            // Log the error (the full chain using the alternate selector), but it doesn't
            // impact the primary duty of this program, which is to post the activity log to
            // Slack.
            // XXX Maybe put some of the non-fatal errors we run into along the way into the
            // Slack message?  Maybe in a separate admin conversation?
            // XXX It'd be nice if anyhow::Error would serialize into JSON.  There's
            // https://github.com/dtolnay/anyhow/issues/67 which was closed due to
            // non-responsiveness.
            error!("Failed to persist activity log: {e:#}");
            // Display a multi-line version with all the struct members.
            debug!("Failed to persist activity log: {e:#?}");
            None
        }
    };

    // Yeah, great name.
    /// Message or Deferred Error.
    enum MoDE {
        Message(String),
        DeferredError(HTTPError),
    }

    // Construct the message we send to Slack.
    // XXX We should continue if we couldn't parse the text as HTML, just putting the text
    // straight into the message.  But for now, just error out.
    let thing = match &al.data.context.activity_log {
        alerts::InnerActivityLog::ServiceHealth(_) => html::build_message(al)
            .http_err_map(
                StatusCode::BAD_REQUEST,
                "Failed to parse communication as HTML".to_string(),
            )
            .map(MoDE::Message),
        alerts::InnerActivityLog::Security(_)
        | alerts::InnerActivityLog::Recommendation(_)
        | alerts::InnerActivityLog::ResourceHealth(_)
        | alerts::InnerActivityLog::Administrative(_) => Ok(MoDE::DeferredError(HTTPError::new(
            StatusCode::NOT_IMPLEMENTED,
            "activity log type not implemented".to_string(),
        ))),
        alerts::InnerActivityLog::Dummy => Err(HTTPError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Dummy event should never happen!".to_string(),
        )),
    }?;

    let secret_name = env_default(EnvDefaults::SlackAPIKeyName);
    let secret = keyvault_get_secret(&secret_name).await.http_err_map(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to get Slack key from Key Vault".to_string(),
    )?;

    let slack_client = SlackClient::new(SlackClientHyperConnector::new());
    let slack_token_value: SlackApiTokenValue = secret.into();
    let slack_token = SlackApiToken::new(slack_token_value);
    let slack_session = slack_client.open_session(&slack_token);
    let slack_auth_test = slack_session.auth_test().await.http_err_map(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to perform an auth test connection to Slack".to_string(),
    )?;

    let user_id = env::var("SLACK_TARGET_USER").http_err_map(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Couldn't find target user in environment variable SLACK_TARGET_USER".to_string(),
    )?;

    let msg = match &thing {
        MoDE::Message(x) => x.clone(),
        MoDE::DeferredError(_) => match doc_id {
            Some(ref x) => {
                // I'd love to provide an Azure Portal link to the document, but AFAICT you can't
                // link directly to it, even though you can query for it in the Cosmos DB API for
                // MongoDB Data Explorer.
                format!("Received an unimplemented activity log type.  See document ID {x}.")
            }
            None => {
                "Received an unimplemented activity log type (failed to save document)".to_string()
            }
        },
    };

    let title = match &al.data.context.activity_log {
        alerts::InnerActivityLog::ServiceHealth(sh) => sh.properties.title.as_ref(),
        _ => "Unimplemented Activity Log Type",
    };

    let metadata_fields = match &al.data.context.activity_log {
        alerts::InnerActivityLog::ServiceHealth(sh) => {
            let doc_id = match doc_id {
                Some(ref x) => x.clone(),
                None => "unknown".to_string(),
            };
            // See if we can make these Context blocks.
            Some(SlackSectionBlock::new().with_fields(vec![
                md!("*Document ID:*\n{}", doc_id),
                md!(
                        "*Tracking ID:*\n<https://app.azure.com/h/{0}/{1}|{0}>",
                        sh.properties.tracking_id,
                        sh.subscription_id
                            .simple()
                            .to_string()
                            .chars()
                            .enumerate()
                            .filter(|&(i, _)| !(4..32 - 4).contains(&i))
                            .map(|(_, c)| c)
                            .collect::<String>()
                    ),
                md!("*Correlation ID:*\n{}", sh.correlation_id),
                md!("*Event Data ID:*\n{}", sh.event_data_id),
                md!("*Operation ID:*\n{}", sh.operation_id),
                md!("*Communication ID:*\n{}", sh.properties.communication_id),
                md!("*Subscription ID:*\n{}", sh.subscription_id), // resolve to name
                md!("*Event Timestamp:*\n{}", sh.event_timestamp),
                md!("*Status:*\n{}", sh.status),
                md!("*Stage:*\n{}", sh.properties.stage),
            ]))
        }
        _ => None,
    };

    let mut blocks: Vec<SlackBlock> = slack_blocks![
        some_into(SlackHeaderBlock::new(pt!(title))),
        optionally_into(metadata_fields.is_some() => metadata_fields.unwrap()),
        some_into(SlackDividerBlock::new())
    ];

    // Slack restricts text blocks to 3000 characters
    blocks.extend(
        split_text(&msg, 3000)
            .into_iter()
            .map(|block_text| SlackSectionBlock::new().with_text(md!(block_text)).into()),
    );
    debug!(
        "Carved {}-character message up into {} blocks: {:?}",
        msg.len(),
        blocks.len(),
        "what"
    );

    // Slack allows a maximum of 50 blocks
    // XXX put the rest into threaded followup(s)
    blocks = blocks.into_iter().take(50).collect();

    let content = SlackMessageContent::new().with_blocks(blocks.clone());

    let req = SlackApiChatPostMessageRequest::new(user_id.into(), content);
    let resp = slack_session
        .chat_post_message(&req)
        .await
        .map_err(|e| {
            debug!("Failed to post message.  Block dump: {:?}", &blocks);
            e
        })
        .http_err_map(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to post message".to_string(),
        )?;

    match thing {
        MoDE::Message(_) => Ok((
            StatusCode::OK,
            format!(
                // Obviously, don't do this for realz
                "Got Service Health event, secret '{secret_name}' is 'LOLZ J/K'.\n\
                 Slack auth test response: {slack_auth_test:?}\n\
                 Slack post message response: {resp:#?}\n"
            ),
        )),
        MoDE::DeferredError(err) => Err(err),
    }
}

// Try to put as many paragraphs into a block as we can.
// Could we do this by using split_text_every_paragraph() and then combining the resulting blocks
// if they're small enough?
#[allow(dead_code)]
fn split_text_fancy(text: &str, max_size: usize) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut block_begin = 0;
    let mut last_pos = 0;

    /*
    let mut do_one_block = |last_pos, pos| {
        println!(
            "do_one_block with last_pos = {last_pos}, pos = {pos}, and block_begin = {block_begin}"
        );
        if pos - block_begin > max_size {
            if let Some(block) = text.get(block_begin..last_pos) {
                println!("New block between {block_begin} and {last_pos}");
                blocks.push(block);
                block_begin = pos + 2;
            } else {
                // We shouldn't ever get here, since pos should always be on a newline character
                // and block_begin should always be on the first byte of whatever follows a newline
                // character.  The message should include the text surrounding pos, but I think if
                // we had a good way of doing that, we'd simply use it to not be in this position
                // in the first place.
                panic!("Couldn't get text between {block_begin} and {pos} (one of the two positions is a byte offset not on a character boundary).");
            }
        }
    };
    */

    for (pos, _) in text.match_indices("\n\n") {
        println!(
            "loop iter with last_pos = {last_pos}, pos = {pos}, and block_begin = {block_begin}"
        );
        if pos - block_begin > max_size {
            if let Some(block) = text.get(block_begin..last_pos) {
                println!(
                    "New block between {block_begin} and {last_pos}: {} chars",
                    block.len()
                );
                blocks.push(block);
                block_begin = pos + 2;
                last_pos = block_begin;
            } else {
                // We shouldn't ever get here, since pos should always be on a newline character
                // and block_begin should always be on the first byte of whatever follows a newline
                // character.  The other possibility is that block_begin > last_pos, which is also
                // a programming logic error.  The message should include the text surrounding pos,
                // but I think if we had a good way of doing that, we'd simply use it to not be in
                // this position in the first place.
                panic!("Couldn't get text between {block_begin} and {pos} (one of the two positions is a byte offset not on a character boundary).");
            }
        } else {
            last_pos = pos;
        }
    }

    println!("out of loop with last_pos = {last_pos} and block_begin = {block_begin}");
    if last_pos > block_begin {
        if let Some(block) = text.get(block_begin..last_pos) {
            println!(
                "New block between {block_begin} and {last_pos}: {} chars",
                block.len()
            );
            blocks.push(block);
            block_begin = last_pos + 2;
        }
    }

    if let Some(block) = text.get(block_begin..) {
        println!(
            "Last block between {block_begin} and END: {} chars",
            block.len()
        );
        blocks.push(block);
    }

    blocks
}

fn process_block<'a>(text: &'a str, maxlen: usize, outvec: &mut Vec<&'a str>) {
    // This will elide paragraphs that are nothing but whitespace.  If that's not desired, then use
    // trim_start_matches('\n').
    let text = text.trim();

    println!("Block {} len {}", outvec.len(), text.len());

    if text.len() <= maxlen {
        outvec.push(text);
        return;
    }

    println!("Block {} is too big! (> {})", outvec.len(), maxlen);
    // XXX Need to figure out a way to prevent infinite recursion!
    let retry = split_text_every_linebreak(text, maxlen);
    outvec.extend(retry.iter());
}

// Just put every paragraph into its own block.  Just hope and pray that none of the blocks turns
// out bigger than 3000 characters (max_size).
fn split_text_every_paragraph(text: &str, maxlen: usize) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut last_pos = 0;
    for (pos, _) in text.match_indices("\n\n") {
        if let Some(block) = text.get(last_pos..pos) {
            process_block(block, maxlen, &mut blocks);
            last_pos = pos + 2;
        } else {
            panic!("Couldn't get text between {last_pos} and {pos} (one of the two positions is a byte offset not on a character boundary).");
        }
    }
    if let Some(block) = text.get(last_pos..) {
        process_block(block, maxlen, &mut blocks);
    }

    println!("{:#?}", blocks);
    blocks
}

fn split_text_every_linebreak(text: &str, maxlen: usize) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut last_pos = 0;
    for (pos, _) in text.match_indices("\n") {
        if let Some(block) = text.get(last_pos..pos) {
            process_block(block, maxlen, &mut blocks);
            last_pos = pos + 2;
        } else {
            panic!("Couldn't get text between {last_pos} and {pos} (one of the two positions is a byte offset not on a character boundary).");
        }
    }
    if let Some(block) = text.get(last_pos..) {
        process_block(block, maxlen, &mut blocks);
    }

    println!("{:#?}", blocks);
    blocks
}

fn split_text(text: &str, max_size: usize) -> Vec<&str> {
    split_text_every_paragraph(text, max_size)
}

#[allow(dead_code)]
fn split_text_paragraphs(text: &str, max_size: usize) -> Vec<String> {
    // This is really allocaty, but it's simple.
    let mut v: Vec<String> = Vec::new();
    for line in text.split("\n\n") {
        // Push the line onto the top element of v unless that would cause that element to exceed
        // 3000 characters (that's what Slack tells us; it doesn't clarify that it's not graphemes
        // or bytes) in length; then push the line into a new element.
        //
        // If we're left with a paragraph that's already over the max, we should try splitting it
        // by line.
        if let Some(last) = v.last_mut() {
            if last.chars().count() + line.chars().count() > max_size {
                v.push(line.to_string());
            } else {
                last.push_str(line);
            }
        } else {
            v.push(line.to_string());
        }
    }
    v
}

#[instrument(skip(doc))]
async fn save_doc(doc: &alerts::ActivityLog) -> Result<InsertOneResult, anyhow::Error> {
    let key_name = env_default(EnvDefaults::CosmosConnectionStringKey);
    let connection_string = keyvault_get_secret(&key_name)
        .await
        .context("failed to get CosmosDB connection string from Key Vault")?;

    let client_options = ClientOptions::parse(&connection_string).await?;

    let client = Client::with_options(client_options)?;

    // The database will get created if it doesn't exist.  Can this behavior be changed?
    let database_name = env_default(EnvDefaults::CosmosDBName);
    let collection_name = env_default(EnvDefaults::CosmosCollectionName);

    let db = client.database(&database_name);
    let collection = db.collection::<alerts::ActivityLog>(&collection_name);

    collection
        .insert_one(doc, None)
        .await
        .context("Failed to insert activity log into DB")
        .map(|x| {
            match x.inserted_id.as_object_id() {
                Some(id) => debug!("Persisted activity log in {database_name}/{collection_name} as document id {id}"),
                None => {
                    warn!("Activity log insertion succeeded, but failed to return object ID: {x:?}")
                }
            };
            x
        })
}

// I'd return the KeyVaultSecret, but the type is inaccessible.
#[instrument]
async fn keyvault_get_secret(secret_name: &str) -> Result<String, anyhow::Error> {
    let vault_name = env_default(EnvDefaults::KeyVaultName);

    trace!("Retrieving secret {secret_name} from Key Vault {vault_name}");

    // On MacOS, a connection to 169.254.169.254 (which happens for the managed identity
    // credential) doesn't always return.  A simple curl to that will hang, too, the first time,
    // and then every connection after that will give "Host is down" until it seems to reset
    // itself.  169.254/16 is used for host-to-host connections when there's no real network.  All
    // references to this I can find are about being unable to connect to a real network, not this
    // problem.  So we'll have to work around it.
    let creds = if uname().unwrap().sysname == "Darwin" {
        trace!("Darwin system; using Azure CLI credential");
        DefaultAzureCredential::with_sources(vec![DefaultAzureCredentialEnum::AzureCli(
            AzureCliCredential {},
        )])
    } else {
        trace!("Using default Azure credential options");
        DefaultAzureCredential::default()
    };

    let client = SecretClient::new(
        &format!("https://{vault_name}.vault.azure.net"),
        std::sync::Arc::new(creds),
    )
    .with_context(|| "failed to initialize Key Vault client".to_string())?;
    trace!("Created client; retrieving secret");

    client
        .get(secret_name)
        .into_future()
        .await
        .with_context(|| format!("failed to retrieve secret '{secret_name}' from Key Vault"))
        .map(|secret| secret.value)
}

#[instrument(skip(_ev))]
async fn handle_security_log(_ev: &alerts::Security) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Security Log event"),
    )
}

#[instrument(skip(_ev))]
async fn handle_recommendation(_ev: &alerts::Recommendation) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Recommendation event"),
    )
}

#[instrument(skip(_ev))]
async fn handle_resource_health(_ev: &alerts::ResourceHealth) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Resource Health event"),
    )
}

#[instrument(skip(_ev))]
async fn handle_administrative(_ev: &alerts::Administrative) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Administrative event"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_split() {
        let buf = indoc! {"
            This is a line.

            This is another line.
        "};
        let v = split_text(buf, 30);
        assert_eq!(v.len(), 2, "buf is '{buf:?}'; v is '{v:?}'");
    }

    #[test]
    fn test_split_par() {
        let buf = indoc! {"
            This is a line.

            This is a new paragraph.
        "};
        // 30 puts us in the middle of the second paragraph:
        //
        // This is a line.\n\nThis is a new paragraph.
        //           1           2         3         4
        // 0123456789012345 6 789012345678901234567890
        let v = split_text(buf, 30);
        println!("buf is '{buf:?}'; v is '{v:?}'");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_split_par_2() {
        let blocks = vec![
            "This is a line.\nThis is another line.",
            "This is a new paragraph.\nAnother second line.\n",
        ];
        let buf = blocks.join("\n\n");
        // 50 puts us in the middle of the second paragraph, and the second paragraph is also under
        // 50 characters:
        // This is a line.\nThis is another line.\n\nThis is a new paragraph.\nAnother second line.
        //           1          2         3           4         5         6          7         8
        // 0123456789012345 6789012345678901234567 8 9012345678901234567890123 45678901234567890123
        let v = split_text(&buf, 50);
        println!("buf is '{buf:?}'\nv (len {}) is {v:?}", v.len());
        assert_eq!(v.len(), blocks.len());
        assert_eq!(v[0].trim(), blocks[0].trim());
        assert_eq!(v[1].trim(), blocks[1].trim());
    }

    #[test]
    fn test_split_par_oops() {
        let buf = indoc! {"
            This is a line.
            This is another line.

            This is a new paragraph.
            Which also has a second line.
        "};
        // 30 puts us in the middle of the first paragraph:
        // This is a line.\nThis is another line.\n\nThis is a new paragraph.\nWhich also has a second line.
        //           1          2         3           4         5         6          7         8         9
        // 0123456789012345 6789012345678901234567 8 9012345678901234567890123 45678901234567890123456789012
        // XXX What should we actually do?
        let v = split_text(buf, 50);
        println!("buf is '{buf:?}'; v is '{v:?}'");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_split_par_3() {
        let blocks = vec![
            "This is a line.\nThis is another line.",
            "This is a new paragraph.\nWhich also has a second line.",
            "Let's try a third paragraph.\nJust in case.\n",
        ];
        let buf = blocks.join("\n\n");
        // This is a line.\nThis is another line.\n\nThis is a new paragraph.\nWhich also has a second line.\n\nLet's try a third paragraph.\nFor now.\n
        //           1          2         3           4         5         6          7         8         9          10        11        12         13
        // 0123456789012345 6789012345678901234567 8 9012345678901234567890123 456789012345678901234567890123 4 56789012345678901234567890123 456789012
        let v = split_text(&buf, 40);
        println!("buf is '{buf:?}'\nv (len {}) is {v:?}", v.len());
        assert_eq!(v.len(), blocks.len());
        assert_eq!(v[0].trim(), blocks[0].trim());
        assert_eq!(v[1].trim(), blocks[1].trim());
        assert_eq!(v[2].trim(), blocks[2].trim());
    }

    #[test]
    fn test_split_par_unicode() {
        // XXX we need to find a test that might make the splitter think a paragraph is longer or
        // shorter than it actually is.
        let buf = indoc! {"
            Þis is a line.
            Þis is another line.

            Þis is a new paragraph.
            Which also has a second line.

            Let's try a third paragraph.
            Just in case.
        "};
        // Þis is a line.\nÞis is another line.\n\nÞis is a new paragraph.\nWhich also has a second line.\n\nWe need a third paragraph.\nFor now.\n
        //          1         2         3          4         5         6          7         8         9          10        11        12
        // 123456789012345 789012345678901234567 8 012345678901234567890123 456789012345678901234567890123 4 567890123456789012345678901 234567890
        let v = split_text(buf, 40);
        println!("buf is '{buf:?}'; v is '{v:?}'");
        assert_eq!(v.len(), 3);
    }

    #[test]
    // Make sure that three blank lines between two paragraphs results in two paragraphs.
    fn test_split_three_blank_lines() {
        let blocks = vec![
            "This is a line.\nThis is another line.",
            "This is a new paragraph.\nAfter three blank lines.\n",
        ];
        let buf = blocks.join("\n\n\n");
        // 50 puts us in the middle of the second paragraph, and the second paragraph is also under
        // 50 characters:
        // This is a line.\nThis is another line.\n\nThis is a new paragraph.\nAnother second line.
        //           1          2         3           4         5         6          7         8
        // 0123456789012345 6789012345678901234567 8 9012345678901234567890123 45678901234567890123
        let v = split_text(&buf, 50);
        println!("buf is '{buf:?}'\nv (len {}) is {v:?}", v.len());
        assert_eq!(v.len(), blocks.len());
        assert_eq!(v[0].trim(), blocks[0].trim());
        assert_eq!(v[1].trim(), blocks[1].trim());
    }

    #[test]
    // Make sure that four blank lines between two paragraphs results in two paragraphs.
    fn test_split_four_blank_lines() {
        let blocks = vec![
            "This is a line.\nThis is another line.",
            "This is a new paragraph.\nAfter four blank lines.\n",
        ];
        let buf = blocks.join("\n\n\n\n");
        // 50 puts us in the middle of the second paragraph, and the second paragraph is also under
        // 50 characters:
        // This is a line.\nThis is another line.\n\nThis is a new paragraph.\nAnother second line.
        //           1          2         3           4         5         6          7         8
        // 0123456789012345 6789012345678901234567 8 9012345678901234567890123 45678901234567890123
        let v = split_text(&buf, 50);
        println!("buf is '{buf:?}'\nv (len {}) is {v:?}", v.len());
        assert_eq!(v.len(), blocks.len());
        assert_eq!(v[0].trim(), blocks[0].trim());
        assert_eq!(v[1].trim(), blocks[1].trim());
    }
}
