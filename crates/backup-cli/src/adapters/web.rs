use std::net::SocketAddr;

use axum::extract::State;
use axum::{Json, Router, routing::get};
use near_mpc_contract_interface::types::EpochId;
use prometheus::{Encoder as _, IntGauge, Registry, TextEncoder};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::ports::ReportBackupStatus;

pub fn status_channel() -> (BackupStatusReporter, watch::Receiver<BackupStatus>) {
    let (sender, receiver) = watch::channel(BackupStatus::default());
    (BackupStatusReporter { sender }, receiver)
}

/// Serves `/health`, `/status` and `/metrics` on `listen_address` until the process exits.
/// Returns an error when the address cannot be bound.
pub async fn spawn_web_server(
    listen_address: SocketAddr,
    status: watch::Receiver<BackupStatus>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_address).await?;
    tracing::info!(%listen_address, "serving /health, /status and /metrics");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router(status)).await {
            tracing::error!(?err, "web server stopped");
        }
    });
    Ok(())
}

fn router(status: watch::Receiver<BackupStatus>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(serve_status))
        .route("/metrics", get(serve_metrics))
        .with_state(status)
}

async fn health() -> &'static str {
    "OK"
}

async fn serve_status(State(status): State<watch::Receiver<BackupStatus>>) -> Json<BackupStatus> {
    Json(status.borrow().clone())
}

async fn serve_metrics(State(status): State<watch::Receiver<BackupStatus>>) -> String {
    render_metrics(&status.borrow())
}

/// Renders the Prometheus exposition of `status`. The gauges are absent until the first
/// backup, mirroring the node's `mpc_last_backup_served_*` metrics; the timestamp gauge
/// stays absent while the backup time is unknown.
fn render_metrics(status: &BackupStatus) -> String {
    let registry = Registry::new();
    if let Some(last_backup) = &status.last_backup {
        register_gauge(
            &registry,
            "backup_cli_last_backup_epoch",
            "Epoch id of the keyset most recently backed up by this service",
            saturating_i64(last_backup.epoch_id.get()),
        );
        if let Some(timestamp_seconds) = last_backup.timestamp_seconds {
            register_gauge(
                &registry,
                "backup_cli_last_backup_timestamp_seconds",
                "Unix time at which keyshares were most recently backed up",
                saturating_i64(timestamp_seconds),
            );
        }
    }

    let mut buffer = vec![];
    TextEncoder::new()
        .encode(&registry.gather(), &mut buffer)
        .expect("encoding into an in-memory buffer cannot fail");
    String::from_utf8(buffer).expect("the text encoder produces UTF-8")
}

fn register_gauge(registry: &Registry, name: &str, help: &str, value: i64) {
    let gauge = IntGauge::new(name, help).expect("gauge names and help texts are static");
    gauge.set(value);
    registry
        .register(Box::new(gauge))
        .expect("each gauge is registered once");
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub struct BackupStatusReporter {
    sender: watch::Sender<BackupStatus>,
}

impl ReportBackupStatus for BackupStatusReporter {
    fn keyset_backed_up(&self, epoch_id: EpochId, timestamp_seconds: Option<u64>) {
        self.sender.send_replace(BackupStatus {
            last_backup: Some(LastBackup {
                epoch_id,
                timestamp_seconds,
            }),
        });
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BackupStatus {
    pub last_backup: Option<LastBackup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LastBackup {
    pub epoch_id: EpochId,
    pub timestamp_seconds: Option<u64>,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    fn status_after_a_backup() -> BackupStatus {
        BackupStatus {
            last_backup: Some(LastBackup {
                epoch_id: EpochId::new(5),
                timestamp_seconds: Some(1_700_000_000),
            }),
        }
    }

    fn status_after_a_restart() -> BackupStatus {
        BackupStatus {
            last_backup: Some(LastBackup {
                epoch_id: EpochId::new(5),
                timestamp_seconds: None,
            }),
        }
    }

    #[tokio::test]
    async fn health__should_answer_ok() {
        // When
        let response = health().await;

        // Then
        assert_eq!(response, "OK");
    }

    #[tokio::test]
    async fn serve_status__should_answer_the_published_status_as_json() {
        // Given
        let (reporter, status) = status_channel();
        reporter.keyset_backed_up(EpochId::new(5), Some(1_700_000_000));

        // When
        let Json(response) = serve_status(State(status)).await;

        // Then
        assert_eq!(
            response.last_backup.map(|b| b.epoch_id),
            Some(EpochId::new(5))
        );
    }

    #[test]
    fn render_metrics__should_render_the_last_backup_gauges() {
        // Given
        let status = status_after_a_backup();

        // When
        let metrics = render_metrics(&status);

        // Then
        assert!(
            metrics.contains("backup_cli_last_backup_epoch 5"),
            "{metrics}"
        );
        assert!(
            metrics.contains("backup_cli_last_backup_timestamp_seconds 1700000000"),
            "{metrics}"
        );
    }

    #[test]
    fn render_metrics__should_render_only_the_epoch_gauge_when_the_backup_time_is_unknown() {
        // Given
        let status = status_after_a_restart();

        // When
        let metrics = render_metrics(&status);

        // Then
        assert!(
            metrics.contains("backup_cli_last_backup_epoch 5"),
            "{metrics}"
        );
        assert!(
            !metrics.contains("backup_cli_last_backup_timestamp_seconds"),
            "{metrics}"
        );
    }

    #[test]
    fn render_metrics__should_render_no_gauges_before_the_first_backup() {
        // Given
        let status = BackupStatus::default();

        // When
        let metrics = render_metrics(&status);

        // Then
        assert_eq!(metrics, "");
    }

    #[test]
    fn keyset_backed_up__should_publish_the_last_backup() {
        // Given
        let (reporter, status) = status_channel();

        // When
        reporter.keyset_backed_up(EpochId::new(5), Some(1_700_000_000));

        // Then
        assert_eq!(*status.borrow(), status_after_a_backup());
    }

    #[test]
    fn keyset_backed_up__should_publish_a_backup_without_a_timestamp() {
        // Given
        let (reporter, status) = status_channel();

        // When
        reporter.keyset_backed_up(EpochId::new(5), None);

        // Then
        assert_eq!(*status.borrow(), status_after_a_restart());
    }

    #[test]
    fn backup_status_json__should_expose_the_last_backup() {
        // Given
        let status = status_after_a_backup();

        // When
        let json = serde_json::to_value(&status).unwrap();

        // Then
        assert_eq!(
            json,
            serde_json::json!({
                "last_backup": { "epoch_id": 5, "timestamp_seconds": 1_700_000_000_u64 }
            })
        );
    }

    #[test]
    fn backup_status_json__should_expose_a_backup_with_an_unknown_time_as_null() {
        // Given
        let status = status_after_a_restart();

        // When
        let json = serde_json::to_value(&status).unwrap();

        // Then
        assert_eq!(
            json,
            serde_json::json!({
                "last_backup": { "epoch_id": 5, "timestamp_seconds": null }
            })
        );
    }
}
