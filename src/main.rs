use axum::{extract::Query, routing::get, Router};
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() {
    let app = Router::new().route("/api/ServiceHealthAlert", get(do_get));

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
