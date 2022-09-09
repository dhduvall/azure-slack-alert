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
use tracing::{debug, error, instrument, trace, warn};
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
    init_logger();

    let app = Router::new().route("/api/ServiceHealthAlert", get(do_get).post(do_post));

    let port: u16 = env_default(EnvDefaults::FunctionsCustomHandlerPort)
        .parse()
        .expect("Custom Handler port in $FUNCTIONS_CUSTOMHANDLER_PORT is not a number!");

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[instrument]
async fn do_get(params: Option<Query<HashMap<String, String>>>) -> String {
    let Query(params) = params.unwrap_or_default();
    match params.get("name") {
        Some(name) => format!("Hello, {name}. This HTTP-triggered function executed successfully."),
        None => "This HTTP-triggered function executed successfully. Pass a name in the query string for a personalized response.".into(),
    }
}

// All the return types must be the same.  If that's not appropriate, we can call .into_response():
// https://docs.rs/axum/0.5.15/axum/response/index.html#returning-different-response-types
#[instrument(skip(v))]
#[debug_handler]
async fn do_post(v: Result<Json<alerts::ActivityLog>, JsonRejection>) -> impl IntoResponse {
    match v {
        Ok(v) => {
            if let Err(e) = save_doc(&v).await {
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
            }

            match &v.data.context.activity_log {
                alerts::InnerActivityLog::ServiceHealth(ev) => {
                    handle_service_health(ev).await.into_response()
                }
                alerts::InnerActivityLog::SecurityLog(ev) => {
                    handle_security_log(ev).await.into_response()
                }
                alerts::InnerActivityLog::Recommendation(ev) => {
                    handle_recommendation(ev).await.into_response()
                }
                alerts::InnerActivityLog::ResourceHealth(ev) => {
                    handle_resource_health(ev).await.into_response()
                }
                alerts::InnerActivityLog::Administrative(ev) => {
                    handle_administrative(ev).await.into_response()
                }
                alerts::InnerActivityLog::Dummy => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Dummy event should never happen!".to_string(),
                )
                    .into_response(),
            }
        }
        Err(JsonRejection::MissingJsonContentType(_)) => {
            // We'll come here if there's no data, too.  This is probably a documentation RFE, at
            // least.
            (
                StatusCode::BAD_REQUEST,
                String::from("Missing JSON content type"),
            )
                .into_response()
        }
        Err(JsonRejection::JsonDataError(_)) => {
            (StatusCode::BAD_REQUEST, String::from("JSON data error")).into_response()
        }
        Err(JsonRejection::JsonSyntaxError(_)) => {
            (StatusCode::BAD_REQUEST, String::from("JSON syntax error")).into_response()
        }
        Err(JsonRejection::BytesRejection(_)) => {
            (StatusCode::BAD_REQUEST, String::from("Bytes Rejection")).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, String::from("Other error")).into_response(),
    }
}

#[instrument(skip(ev))]
// #[debug_handler]
async fn handle_service_health(
    ev: &alerts::ServiceHealth,
) -> axum::response::Result<(StatusCode, String)> {
    // XXX We should continue if we couldn't parse the text as HTML; we just put the text straight
    // into the message.  But for now, just error out.
    // XXX It would be nice to make these map_err() calls more compact, maybe by having a map_ise()
    // function.  But the map_err() argument is a function that takes a single Error argument, and
    // we'd need to be able to pass the string, too.  Can we do something like have map_ise()
    // return a function that does the right thing, and then put map_ise(msg) as the argument to
    // map_err()?
    let msg = html::build_message(ev).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse communication as HTML: {e}"),
        )
    })?;

    let secret_name = env_default(EnvDefaults::SlackAPIKeyName);
    let secret = keyvault_get_secret(&secret_name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let slack_client = SlackClient::new(SlackClientHyperConnector::new());
    let slack_token_value: SlackApiTokenValue = secret.into();
    let slack_token = SlackApiToken::new(slack_token_value);
    let slack_session = slack_client.open_session(&slack_token);
    let slack_auth_test = slack_session.auth_test().await.map_err(|e| {
        // XXX Could run api_test() here to make sure basic connectivity is okay.
        debug!("Slack auth test failure: {e:#?}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to perform an auth test connection to Slack: {e:#?}"),
        )
    })?;

    // XXX Maybe this should come from a query parameter?
    let user_id = env::var("SLACK_TARGET_USER").map_err(|_| {
        debug!("Couldn't find target user in environment variable SLACK_TARGET_USER");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Service configured incorrectly".to_string(),
        )
    })?;
    let content = SlackMessageContent::new().with_text(msg);
    let req = SlackApiChatPostMessageRequest::new(user_id.into(), content);
    let resp = slack_session.chat_post_message(&req).await.map_err(|e| {
        debug!("Slack message post failure: {e:#?}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to post message: {e:#?}"),
        )
    })?;

    Ok((
        StatusCode::OK,
        format!(
            // Obviously, don't do this for realz
            "Got Service Health event, secret '{secret_name}' is 'LOLZ J/K'.\n\
             Slack auth test response: {slack_auth_test:?}\n\
             Slack post message response: {resp:#?}\n"
        ),
    ))
}

#[instrument(skip(doc))]
async fn save_doc(Json(doc): &Json<alerts::ActivityLog>) -> Result<InsertOneResult, anyhow::Error> {
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
async fn handle_security_log(_ev: &alerts::SecurityLog) -> impl IntoResponse {
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
