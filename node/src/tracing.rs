use crate::cli::LogFormat;

pub fn init_logging(log_format: LogFormat) {
    match log_format {
        LogFormat::Json => init_json_logging(),
        LogFormat::Plain => init_plain_logging(),
    }
}

fn init_plain_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
}

fn init_json_logging() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
}
