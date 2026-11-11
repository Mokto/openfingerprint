mod automation;
mod behavior;
mod cache;
mod check;
mod collect;
mod country;
mod domains;
mod email;
mod mailauth;
mod metrics;
mod mx;
mod network;
mod providers;
mod rdap;
mod replay;
mod rpc;
mod spoofing;
mod tampering;
mod tld;
mod tls;
mod whois;

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
    observed(
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/v1/check", post(check::check))
            .merge(rpc::routes(state.clone()))
            .layer(DefaultBodyLimit::max(check::BODY_LIMIT))
            .with_state(state),
    )
}

fn observed(router: Router) -> Router {
    router
        .layer(middleware::from_fn(no_store))
        .layer(middleware::from_fn(observe))
}

async fn metrics(State(state): State<Arc<check::AppState>>) -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.domains.metrics()
            + &state.dns.metrics()
            + &state.rdap.metrics()
            + &state.countries.metrics()
            + &state.network.metrics()
            + &state.replay.metrics()
            + &automation::metrics()
            + &spoofing::metrics()
            + &collect::metrics()
            + &metrics::render(),
    )
}

async fn observe(request: Request, next: Next) -> Response {
    let route = metrics::route(request.uri().path());
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    metrics::observe_request(route, response.status().as_u16(), started.elapsed());
    response
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
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "--validate-country") && (2..=3).contains(&args.len()) {
        country::validate(
            std::path::Path::new(&args[1]),
            args.get(2).map(std::path::Path::new),
        )?;
        return Ok(());
    }
    if let [flag, path] = args.as_slice()
        && flag == "--validate-network-data"
    {
        network::validate(std::path::Path::new(path))?;
        println!("Network snapshot is valid.");
        return Ok(());
    }
    if let [flag, path] = args.as_slice()
        && flag == "--lock-network-data"
    {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|_| "Network updater lock unavailable")?;
        lock.try_lock()
            .map_err(|_| "Network updater lock unavailable")?;
        println!("Network updater lock acquired.");
        std::io::copy(&mut std::io::stdin(), &mut std::io::sink())?;
        return Ok(());
    }
    if !args.is_empty() {
        return Err("Unknown arguments".into());
    }
    let mut options = sentry::ClientOptions::default();
    options.release = sentry::release_name!();
    options.before_send = Some(Arc::new(|mut event| {
        event.request = None;
        event.user = None;
        event.breadcrumbs.values.clear();
        Some(event)
    }));
    let _sentry = sentry::init(options);
    let state = Arc::new(check::AppState::from_env()?);
    if state.network.reloads() {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await;
            loop {
                tick.tick().await;
                let state = state.clone();
                let _ = tokio::task::spawn_blocking(move || state.network.reload()).await;
            }
        });
    }
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
    if state.countries.reloads() {
        let seconds = match std::env::var("OPENFINGERPRINT_COUNTRY_DATA_RELOAD_SECONDS") {
            Err(_) => 60,
            Ok(s) => s
                .parse()
                .ok()
                .filter(|s| (1..=86400).contains(s))
                .ok_or("OPENFINGERPRINT_COUNTRY_DATA_RELOAD_SECONDS must be 1-86400")?,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(seconds));
            tick.tick().await;
            loop {
                tick.tick().await;
                let state = state.clone();
                let _ = tokio::task::spawn_blocking(move || state.countries.reload()).await;
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
    if let Some(config) = collect::config_from_env()? {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = collect::serve(config, state, observed).await {
                eprintln!("Collection listener failed: {error}");
                std::process::exit(1);
            }
        });
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
