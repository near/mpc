use mpc_node_config::{LogConfig, LogFormat};
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::{fs, io};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt, registry};

pub fn init_logging(log_config: &LogConfig) -> (WorkerGuard, std::path::PathBuf) {
    let filter = env_filter(log_config.filter.as_deref());

    let stdout_layer = match log_config.format {
        LogFormat::Json => fmt::layer().json().boxed(),
        LogFormat::Plain => fmt::layer().boxed(),
    };
    let log_dir = get_log_dir_from_config(log_config);
    let _ = fs::create_dir_all(&log_dir);
    let file_appender = tracing_appender::rolling::hourly(&log_dir, "mpc");
    let (non_blocking_writer, log_guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = match log_config.format {
        LogFormat::Json => fmt::layer()
            .json()
            .with_writer(non_blocking_writer)
            .with_ansi(false)
            .boxed(),
        LogFormat::Plain => fmt::layer()
            .with_writer(non_blocking_writer)
            .with_ansi(false)
            .boxed(),
    };
    registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
    (log_guard, log_dir)
}

fn env_filter(filter: Option<&str>) -> EnvFilter {
    match filter {
        Some(f) => EnvFilter::new(f),
        None => EnvFilter::from_default_env(),
    }
}

fn get_log_dir_from_config(log_config: &LogConfig) -> PathBuf {
    log_config.log_dir.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| ".".into())
            .join("logs")
    })
}

pub fn spawn_periodic_prune(handle: &tokio::runtime::Handle, log_config: &LogConfig) {
    let log_dir = get_log_dir_from_config(log_config);
    if let Some(max_log_files) = log_config.max_log_files {
        handle.spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60 * 60));
            loop {
                ticker.tick().await;
                let dir = log_dir.clone();
                let result =
                    tokio::task::spawn_blocking(move || prune_logs(&dir, max_log_files)).await;
                if let Err(err) = result {
                    tracing::warn!(?err, ?log_dir, "failed to prune old logs");
                }
            }
        });
    } else {
        tracing::warn!(
            ?log_dir,
            "max log files not set in config, log cleanup skipped"
        );
    }
}

fn prune_logs(log_dir: &Path, max_log_files: usize) -> io::Result<()> {
    let mut files = fs::read_dir(log_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("mpc"))
        .collect::<Vec<_>>();
    files.sort_by_key(|entry| entry.file_name());
    let excess = files.len().saturating_sub(max_log_files);
    for entry in files.into_iter().take(excess) {
        fs::remove_file(entry.path())?;
    }
    Ok(())
}
