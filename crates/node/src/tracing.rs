use crate::config::start::{LogConfig, LogFormat};
use tracing_subscriber::EnvFilter;

const RUST_BACKTRACE: &str = "RUST_BACKTRACE";

pub fn init_logging(log_config: &LogConfig) {
    if let Some(rust_backtrace) = &log_config.rust_backtrace {
        set_rust_backtrace(rust_backtrace.clone());
    }

    let filter = env_filter(log_config.filter.as_deref());

    match log_config.format {
        LogFormat::Json => init_json_logging(filter),
        LogFormat::Plain => init_plain_logging(filter),
    }
}

fn set_rust_backtrace(rust_backtrace_value: String) {
    unsafe {
        std::env::set_var(RUST_BACKTRACE, rust_backtrace_value);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_fork::rusty_fork_test;

    // Tests run in forked subprocesses to avoid mutating the env of other tests
    rusty_fork_test! {
        #[test]
        fn init_logging_sets_rust_backtrace_when_configured() {
            let foo_backtrace = "FOO_BACKTRACE".to_string();

            let config = LogConfig {
                format: LogFormat::Plain,
                filter: None,
                rust_backtrace: Some(foo_backtrace.clone()),
            };
            init_logging(&config);

            let backtrace_value = std::env::var(RUST_BACKTRACE).expect("init_logging set backtrace value");

            assert_eq!(backtrace_value, foo_backtrace);
        }
    }
}
