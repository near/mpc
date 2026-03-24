use tracing_subscriber::EnvFilter;

use crate::config::start::{LogConfig, LogFormat};

pub fn init_logging(log_config: &LogConfig) {
    let filter = env_filter(log_config.filter.as_deref());

    match log_config.format {
        LogFormat::Json => init_json_logging(filter),
        LogFormat::Plain => init_plain_logging(filter),
    }
}

fn env_filter(filter: Option<&str>) -> EnvFilter {
    match filter {
        Some(f) => EnvFilter::new(f),
        None => EnvFilter::from_default_env(),
    }
}

fn init_plain_logging(filter: EnvFilter) {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .ok();
}

fn init_json_logging(filter: EnvFilter) {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .try_init()
        .ok();
}
