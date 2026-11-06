mod verify;

use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    extract::Request,
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};

fn app(state: Arc<verify::AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/verify", post(verify::verify))
        .layer(DefaultBodyLimit::max(verify::BODY_LIMIT))
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

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(verify::AppState::from_env()?);
    let addr =
        std::env::var("OPENFINGERPRINT_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8180".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
