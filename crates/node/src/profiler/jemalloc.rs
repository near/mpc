use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::{ffi::c_void, fs::File, io::BufReader};

const CONTENT_TYPE_SVG: &str = "image/svg+xml";
const CONTENT_TYPE_PPROF: &str = "application/octet-stream";

const MSG_PROFILING_UNAVAILABLE: &str =
    "jemalloc heap profiling is not available; ensure the binary was built with the `profiling` feature \
     and started with `MALLOC_CONF=prof:true,prof_active:true`";
const MSG_PROFILING_INACTIVE: &str = "jemalloc heap profiling is not active";

// Hold the profiler lock only long enough to acquire the heap dump file.
// Post-processing (symbolication, flamegraph rendering, pprof encoding) can
// then run on the blocking pool without keeping the profiler locked or
// stalling the async runtime.
async fn dump_heap_file() -> Result<File, Response> {
    let Some(prof_ctl_mutex) = jemalloc_pprof::PROF_CTL.as_ref() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, MSG_PROFILING_UNAVAILABLE).into_response());
    };

    let mut prof_ctl = prof_ctl_mutex.lock().await;
    if !prof_ctl.activated() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, MSG_PROFILING_INACTIVE).into_response());
    }
    prof_ctl.dump().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to dump heap profile: {err:#}"),
        )
            .into_response()
    })
}

pub(super) async fn jemalloc_heap_flamegraph() -> impl IntoResponse {
    let dump_file = match dump_heap_file().await {
        Ok(file) => file,
        Err(response) => return response,
    };

    let svg_result = tokio::task::spawn_blocking(move || render_flamegraph_svg(dump_file)).await;

    match svg_result {
        Ok(Ok(svg)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, CONTENT_TYPE_SVG)],
            svg,
        )
            .into_response(),
        Ok(Err(err)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to render heap flamegraph: {err:#}"),
        )
            .into_response(),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("flamegraph task panicked: {join_err}"),
        )
            .into_response(),
    }
}

pub(super) async fn jemalloc_heap_pprof() -> impl IntoResponse {
    let dump_file = match dump_heap_file().await {
        Ok(file) => file,
        Err(response) => return response,
    };

    let pprof_result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let profile = pprof_util::parse_jeheap(BufReader::new(dump_file), None)?;
        Ok(profile.to_pprof(("inuse_space", "bytes"), ("space", "bytes"), None))
    })
    .await;

    match pprof_result {
        Ok(Ok(bytes)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, CONTENT_TYPE_PPROF),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"heap.pb.gz\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Ok(Err(err)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode pprof profile: {err:#}"),
        )
            .into_response(),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pprof task panicked: {join_err}"),
        )
            .into_response(),
    }
}

fn render_flamegraph_svg(dump_file: File) -> anyhow::Result<Vec<u8>> {
    let stack_profile = pprof_util::parse_jeheap(BufReader::new(dump_file), None)?;

    let mut collapsed_lines: Vec<String> = Vec::with_capacity(stack_profile.stacks.len());
    for (stack, _annotation) in &stack_profile.stacks {
        // Heap dumps weight each sample by allocated bytes (a float). Inferno
        // expects a non-negative integer count, so round up to ensure samples
        // are never silently dropped.
        let weight = stack.weight.max(0.0).ceil() as u64;
        if weight == 0 {
            continue;
        }

        // `parse_jeheap` returns frames root-first, which is also what inferno's
        // collapsed format expects, so no reordering is needed here.
        let frames: Vec<String> = stack
            .addrs
            .iter()
            .map(|&addr| symbolicate(addr))
            .collect();

        collapsed_lines.push(format!("{} {}", frames.join(";"), weight));
    }

    let mut svg = Vec::new();
    let mut opts = inferno::flamegraph::Options::default();
    opts.title = "jemalloc heap profile".to_string();
    opts.count_name = "bytes".to_string();
    inferno::flamegraph::from_lines(
        &mut opts,
        collapsed_lines.iter().map(String::as_str),
        &mut svg,
    )?;

    Ok(svg)
}

fn symbolicate(addr: usize) -> String {
    let mut resolved: Option<String> = None;
    backtrace::resolve(addr as *mut c_void, |sym| {
        if resolved.is_some() {
            return;
        }
        if let Some(name) = sym.name() {
            // SymbolName::Display demangles automatically.
            resolved = Some(name.to_string());
        }
    });

    resolved.unwrap_or_else(|| format!("0x{addr:x}"))
}
