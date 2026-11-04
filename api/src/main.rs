mod email;
mod poc;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    extract::Request,
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};

fn app(state: Arc<poc::AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/collect", post(poc::collect).options(poc::preflight))
        .route("/v1/check", post(poc::check))
        .layer(DefaultBodyLimit::max(poc::BODY_LIMIT))
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(poc::AppState::from_env()?);
    let cleanup = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup.cleanup();
        }
    });
    let addr =
        std::env::var("OPENFINGERPRINT_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8180".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app(state)).await?;
    Ok(())
}
