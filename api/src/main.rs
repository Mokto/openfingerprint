mod automation;
mod cache;
mod check;
mod collection;
mod domains;
mod mx;
mod rdap;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    extract::{Request, State},
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};

fn app(state: Arc<check::AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/check", post(check::check))
        .route("/v1/verify", post(check::verify))
        .route("/v1/challenges", post(collection::challenge))
        .route("/v1/collect", post(collection::collect))
        .route("/v1/events/consume", post(collection::consume))
        .layer(DefaultBodyLimit::max(check::BODY_LIMIT))
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

async fn metrics(State(state): State<Arc<check::AppState>>) -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.domains.metrics() + &state.dns.metrics() + &state.rdap.metrics(),
    )
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
    let state = Arc::new(check::AppState::from_env()?);
    if state.domains.reloads() {
        let seconds = match std::env::var("OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS") {
            Err(_) => 60,
            Ok(s) => s
                .parse()
                .ok()
                .filter(|s| (1..=86400).contains(s))
                .ok_or("OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS must be 1-86400")?,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(seconds));
            tick.tick().await;
            loop {
                tick.tick().await;
                let state = state.clone();
                let _ = tokio::task::spawn_blocking(move || state.domains.reload()).await;
            }
        });
    }
    if let Ok(addr) = std::env::var("OPENFINGERPRINT_METRICS_ADDR") {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!("metrics on {}", listener.local_addr()?);
        let router = Router::new()
            .route("/metrics", get(metrics))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, router).await });
    }
    let addr =
        std::env::var("OPENFINGERPRINT_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8180".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
