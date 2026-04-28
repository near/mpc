use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::{ffi::c_void, fs::File, io::BufReader};

const CONTENT_TYPE_SVG: &str = "image/svg+xml";
const CONTENT_TYPE_PPROF: &str = "application/octet-stream";

// Content-Disposition header for the pprof endpoint; pins the saved filename
// to `heap.pb.gz` so `go tool pprof` / `pprof` recognize it as gzipped pprof.
const CONTENT_DISPOSITION_PPROF: &str = "attachment; filename=\"heap.pb.gz\"";

// Title rendered at the top of the flamegraph SVG.
const FLAMEGRAPH_TITLE: &str = "jemalloc heap profile";
// Unit label for sample weights in the flamegraph; each stack is weighted by
// allocated bytes.
const FLAMEGRAPH_COUNT_NAME: &str = "bytes";

// pprof sample type: bytes currently allocated and not yet freed (live heap).
// Tuple is (name, unit) per the pprof proto spec.
const PPROF_SAMPLE_TYPE: (&str, &str) = ("inuse_space", "bytes");
// pprof period type: the unit between successive samples, matching the sample
// type for a heap profile.
const PPROF_PERIOD_TYPE: (&str, &str) = ("space", "bytes");

const MSG_PROFILING_UNAVAILABLE: &str =
    "jemalloc heap profiling is not available; ensure the binary was built with the `profiling` feature \
     and started with `MALLOC_CONF=prof:true,prof_active:true`";

// Returned when profiling is compiled in but currently paused
// (`prof_active:false` at runtime).
const MSG_PROFILING_INACTIVE: &str = "jemalloc heap profiling is not active";

async fn dump_heap_file() -> Result<File, Response> {
    let Some(prof_ctl_mutex) = jemalloc_pprof::PROF_CTL.as_ref() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, MSG_PROFILING_UNAVAILABLE).into_response());
    };

    let mut prof_ctl = prof_ctl_mutex.lock().await;
    if !prof_ctl.activated() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, MSG_PROFILING_INACTIVE).into_response());
    }

    // `prof_ctl.dump()` is using blocking IO
    tokio::task::spawn_blocking(move || prof_ctl.dump())
        .await
        .map_err(|join_error: tokio::task::JoinError| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed joining on tokio task: {:?}", join_error),
            )
                .into_response()
        })?
        .map_err(|err| {
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
        // Embed runtime binary mappings so pprof can relocate addresses through
        // ASLR; without this every frame collapses to the binary's mapping name.
        let profile =
            pprof_util::parse_jeheap(BufReader::new(dump_file), mappings::MAPPINGS.as_deref())?;
        Ok(profile.to_pprof(PPROF_SAMPLE_TYPE, PPROF_PERIOD_TYPE, None))
    })
    .await;

    match pprof_result {
        Ok(Ok(bytes)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, CONTENT_TYPE_PPROF),
                (header::CONTENT_DISPOSITION, CONTENT_DISPOSITION_PPROF),
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

        let frames: Vec<String> = stack.addrs.iter().map(|&addr| symbolicate(addr)).collect();

        collapsed_lines.push(format!("{} {}", frames.join(";"), weight));
    }

    let mut svg = Vec::new();
    let mut opts = inferno::flamegraph::Options::default();
    opts.title = FLAMEGRAPH_TITLE.to_string();
    opts.count_name = FLAMEGRAPH_COUNT_NAME.to_string();
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
            resolved = Some(name.to_string());
        }
    });

    resolved.unwrap_or_else(|| format!("0x{addr:x}"))
}
