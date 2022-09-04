use axum::{
    extract::{rejection::JsonRejection, Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use azure_identity::{AzureCliCredential, DefaultAzureCredential, DefaultAzureCredentialEnum};
use azure_security_keyvault::SecretClient;
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{instrument, trace};
use tracing_subscriber;
use uname::uname;

pub mod alerts;

#[tokio::main]
#[instrument]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/api/ServiceHealthAlert", get(do_get).post(do_post));

    let port_envvar = "FUNCTIONS_CUSTOMHANDLER_PORT";
    let port: u16 = match env::var(port_envvar) {
        Ok(val) => val
            .parse()
            .expect("Custom Handler port in $FUNCTIONS_CUSTOMHANDLER_PORT is not a number!"),
        Err(_) => 3000,
    };

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
        Some(name) => format!("Hello, {}. This HTTP-triggered function executed successfully.", name),
        None => String::from("This HTTP-triggered function executed successfully. Pass a name in the query string for a personalized response."),
    }
}

// All the return types must be the same.  If that's not appropriate, we can call .into_response():
// https://docs.rs/axum/0.5.15/axum/response/index.html#returning-different-response-types
#[instrument(skip(v))]
async fn do_post(v: Result<Json<alerts::ActivityLog>, JsonRejection>) -> impl IntoResponse {
    match v {
        Ok(v) => match &v.data.context.activity_log {
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
                format!("Dummy event should neverhappen!"),
            )
                .into_response(),
        },
        Err(JsonRejection::MissingJsonContentType(_)) => {
            // We'll come here if there's no data, too.  This is probably a documentation RFE, at
            // least.
            return (
                StatusCode::BAD_REQUEST,
                String::from("Missing JSON content type"),
            )
                .into_response();
        }
        Err(JsonRejection::JsonDataError(_)) => {
            return (StatusCode::BAD_REQUEST, String::from("JSON data error")).into_response();
        }
        Err(JsonRejection::JsonSyntaxError(_)) => {
            return (StatusCode::BAD_REQUEST, String::from("JSON syntax error")).into_response();
        }
        Err(JsonRejection::BytesRejection(_)) => {
            return (StatusCode::BAD_REQUEST, String::from("Bytes Rejection")).into_response();
        }
        Err(_) => {
            return (StatusCode::BAD_REQUEST, String::from("Other error")).into_response();
        }
    }
}

#[instrument(skip(_ev))]
async fn handle_service_health(
    _ev: &alerts::ServiceHealth,
) -> axum::response::Result<(StatusCode, String)> {
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

    let vault_name = env::var("KEYVAULT_NAME").unwrap_or("coros-svc-health-alert".to_string());

    let client = SecretClient::new(
        &format!("https://{vault_name}.vault.azure.net"),
        std::sync::Arc::new(creds),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from(format!("Failed to initialize Key Vault client: {e}")),
        )
    })?;
    trace!("Created client; retrieving secret");

    let secret_name = env::var("SLACK_API_KEY_NAME").unwrap_or("slack-bot-oauth-token".to_string());
    // It would be nice to make this map_err() call more compact, maybe by having a map_ise()
    // function.  But the map_err() argument is a function that takes a single Error argument, and
    // we'd need to be able to pass the string, too.  Can we do something like have map_ise()
    // return a function that does the right thing, and then put map_ise(msg) as the argument to
    // map_err()?
    let secret = client.get(&secret_name).into_future().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from(format!(
                "Failed to retrieve secret '{secret_name}' from Key Vault: {e}"
            )),
        )
    })?;

    Ok((
        StatusCode::OK,
        String::from(format!(
            "Got Service Health event, secret '{secret_name}' is '{}'",
            secret.value,
        )),
    ))
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
