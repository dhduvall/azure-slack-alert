use axum::{
    extract::{rejection::JsonRejection, Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};

pub mod alerts;

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

// All the return types must be the same.  If that's not appropriate, we can call .into_response():
// https://docs.rs/axum/0.5.15/axum/response/index.html#returning-different-response-types
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

async fn handle_service_health(_ev: &alerts::ServiceHealth) -> impl IntoResponse {
    (StatusCode::OK, String::from("Got Service Health event"))
}

async fn handle_security_log(_ev: &alerts::SecurityLog) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Security Log event"),
    )
}

async fn handle_recommendation(_ev: &alerts::Recommendation) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Recommendation event"),
    )
}

async fn handle_resource_health(_ev: &alerts::ResourceHealth) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Resource Health event"),
    )
}

async fn handle_administrative(_ev: &alerts::Administrative) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        String::from("Got unexpected Administrative event"),
    )
}
