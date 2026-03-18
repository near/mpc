use tracing::Level;
use tracing_subscriber::EnvFilter;

use crate::config::start::{LogConfig, LogFormat, LogLevel};

pub fn init_logging(log_config: &LogConfig) {
    let log_level = log_config.log_level.as_ref().map(|l| match l {
        LogLevel::Trace => Level::TRACE,
        LogLevel::Debug => Level::DEBUG,
        LogLevel::Info => Level::INFO,
        LogLevel::Warn => Level::WARN,
        LogLevel::Error => Level::ERROR,
    });

    match log_config.log_format {
        LogFormat::Json => init_json_logging(log_level),
        LogFormat::Plain => init_plain_logging(log_level),
    }
}

fn env_filter(log_level: Option<Level>) -> EnvFilter {
    match log_level {
        Some(level) => EnvFilter::new(level.as_str()),
        None => EnvFilter::from_default_env(),
    }
}

fn init_plain_logging(log_level: Option<Level>) {
    tracing_subscriber::fmt()
        .with_env_filter(env_filter(log_level))
        .try_init()
        .ok();
}

fn init_json_logging(log_level: Option<Level>) {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(env_filter(log_level))
        .try_init()
        .ok();
}
