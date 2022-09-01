use axum::{
    extract::{rejection::JsonRejection, Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() {
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

async fn do_get(params: Option<Query<HashMap<String, String>>>) -> String {
    let Query(params) = params.unwrap_or_default();
    match params.get("name") {
        Some(name) => format!("Hello, {}. This HTTP-triggered function executed successfully.", name),
        None => String::from("This HTTP-triggered function executed successfully. Pass a name in the query string for a personalized response."),
    }
}

// XXX Value is probably just a stand-in for now; will probably want to have real data structures
// for the alerts.
// All the return types must be the same.  If that's not appropriate, we can call .into_response():
// https://docs.rs/axum/0.5.15/axum/response/index.html#returning-different-response-types
async fn do_post(v: Result<Json<Value>, JsonRejection>) -> impl IntoResponse {
    match v {
        Ok(v) => {
            // yay!
            if v["schemaId"] != "Microsoft.Insights/activityLogs" {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Unexpected schemaId '{}'", v["schemaId"]),
                );
            }

            let event_source = &v["data"]["context"]["activityLog"]["eventSource"];
            if event_source != "ServiceHealth" {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Unexpected event '{}'", event_source),
                );
            }

            return (StatusCode::OK, String::from("OKAY!"));
        }
        Err(JsonRejection::MissingJsonContentType(_)) => {
            // We'll come here if there's no data, too.  This is probably a documentation RFE, at
            // least.
            return (
                StatusCode::BAD_REQUEST,
                String::from("Missing JSON content type"),
            );
        }
        Err(JsonRejection::JsonDataError(_)) => {
            return (StatusCode::BAD_REQUEST, String::from("JSON data error"));
        }
        Err(JsonRejection::JsonSyntaxError(_)) => {
            return (StatusCode::BAD_REQUEST, String::from("JSON syntax error"));
        }
        Err(JsonRejection::BytesRejection(_)) => {
            return (StatusCode::BAD_REQUEST, String::from("Bytes Rejection"));
        }
        Err(_) => {
            return (StatusCode::BAD_REQUEST, String::from("Other error"));
        }
    }
}
