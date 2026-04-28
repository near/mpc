use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};

const CONTENT_TYPE_PPROF: &str = "application/octet-stream";

const MSG_PROFILING_UNAVAILABLE: &str =
    "jemalloc heap profiling is not available; ensure the binary was built with the `profiling` feature \
     and started with `MALLOC_CONF=prof:true,prof_active:true`";
const MSG_PROFILING_INACTIVE: &str = "jemalloc heap profiling is not active";

pub(super) async fn jemalloc_heap_profile() -> impl IntoResponse {
    let Some(prof_ctl_mutex) = jemalloc_pprof::PROF_CTL.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, MSG_PROFILING_UNAVAILABLE).into_response();
    };

    let mut prof_ctl = prof_ctl_mutex.lock().await;
    if !prof_ctl.activated() {
        return (StatusCode::SERVICE_UNAVAILABLE, MSG_PROFILING_INACTIVE).into_response();
    }

    match prof_ctl.dump_pprof() {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, CONTENT_TYPE_PPROF)],
            bytes,
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to dump heap profile: {err:#}"),
        )
            .into_response(),
    }
}
