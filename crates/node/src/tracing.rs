use mpc_node_config::{LogConfig, LogFormat};
use std::path::Path;
use std::time::SystemTime;
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
    let log_dir = log_config.log_dir.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| ".".into())
            .join("logs")
    });
    let _ = fs::create_dir_all(&log_dir);
    if let Some(max_log_files) = log_config.max_log_files {
        let _ = prune_logs(&log_dir, max_log_files);
    }
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

fn prune_logs(log_dir: &Path, max_log_files: usize) -> io::Result<()> {
    let mut files = fs::read_dir(log_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("mpc"))
        .collect::<Vec<_>>();

    files.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    let excess = files.len().saturating_sub(max_log_files);
    for entry in files.into_iter().take(excess) {
        fs::remove_file(entry.path())?;
    }
    Ok(())
}
