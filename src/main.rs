use axum::{
    routing::{get, post},
    Router,
    response::Html,
};
use tower_http::cors::CorsLayer;
use tracing_subscriber;

mod handlers;
mod models;
mod error;

use handlers::*;

async fn serve_index() -> Html<&'static str> {
    Html(include_str!("../index.html"))
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    tracing::info!("Starting Solana HTTP Server");

    // Build our application with routes
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    // Bind to 0.0.0.0:5000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:5000")
        .await
        .expect("Failed to bind to address");
    
    tracing::info!("Server running on http://0.0.0.0:5000");
    
    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}