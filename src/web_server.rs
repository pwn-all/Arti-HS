use anyhow::Result;
use axum::{
    Json, Router,
    body::Body,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Request, Response},
    middleware::Next,
    routing::get,
};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HyperBuilder,
};
use serde::Serialize;
use std::convert::Infallible;
use std::sync::Arc;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;
use tower::Service;

const MAX_BODY_BYTES: usize = 96 * 1024;

pub type AppService = Router;
#[derive(Serialize)]
struct StatusResponse {
    status: bool,
    error: Option<String>,
}

async fn status_handler() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: true,
        error: None,
    })
}

async fn security_headers(req: Request<Body>, next: Next) -> Result<Response<Body>, Infallible> {
    let mut res = next.run(req).await;

    let h = res.headers_mut();

    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("Server", HeaderValue::from_static("nginx/1.29.4"));
    h.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    Ok(res)
}

pub fn app_service() -> AppService {
    Router::new()
        .route("/", get(status_handler))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(security_headers))
}

pub async fn handle_client(req: StreamRequest, app_service: Arc<AppService>) -> Result<()> {
    let conn = req.accept(Connected::new_empty()).await?;

    let io = TokioIo::new(conn);

    HyperBuilder::new(TokioExecutor::new())
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let mut svc = (*app_service).clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let req = Request::from_parts(parts, Body::new(body));
                    svc.call(req).await.map_err(anyhow::Error::from)
                }
            }),
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}
