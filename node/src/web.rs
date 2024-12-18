#[cfg(not(test))]
use crate::config::WebUIConfig;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
#[cfg(not(test))]
use axum::{routing::get, Router};
#[cfg(not(test))]
use futures::future::BoxFuture;
#[cfg(not(test))]
use futures::FutureExt;
use prometheus::{default_registry, Encoder, TextEncoder};
/// Wrapper to make Axum understand how to convert anyhow::Error into a 500
/// response.
pub(crate) struct AnyhowErrorWrapper(anyhow::Error);

impl From<anyhow::Error> for AnyhowErrorWrapper {
    fn from(e: anyhow::Error) -> Self {
        AnyhowErrorWrapper(e)
    }
}

impl IntoResponse for AnyhowErrorWrapper {
    fn into_response(self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("{:?}", self.0)))
            .unwrap()
    }
}

pub(crate) async fn metrics() -> String {
    let metric_families = default_registry().gather();
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Starts the web server. This is an async function that returns a future.
/// The function itself will return error if the server cannot be started.
///
/// The returned future is the one that actually serves. It will be
/// long-running, and is typically not expected to return. However, dropping
/// the returned future will stop the web server.
#[cfg(not(test))]
pub async fn start_web_server(
    config: WebUIConfig,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    let router = Router::new().route("/metrics", get(metrics));

    let tcp_listener =
        tokio::net::TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;
    Ok(async move {
        axum::serve(tcp_listener, router).await?;
        anyhow::Ok(())
    }
    .boxed())
}
