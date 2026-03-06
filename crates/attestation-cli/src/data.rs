use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use node_types::http_server::StaticWebData;

use crate::cli::Source;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn load_static_web_data(source: &Source) -> anyhow::Result<StaticWebData> {
    match source {
        Source::Url { url } => fetch_from_url(url).await,
        Source::File { path } => load_from_file(path),
    }
}

async fn fetch_from_url(url: &url::Url) -> anyhow::Result<StaticWebData> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("failed to build HTTP client")?;

    let response = client
        .get(url.as_str())
        .send()
        .await
        .with_context(|| format!("failed to fetch from {url}"))?;

    let status = response.status();
    if !status.is_success() {
        bail!("HTTP request to {url} returned status {status}");
    }

    let data: StaticWebData = response
        .json()
        .await
        .context("failed to parse response JSON as StaticWebData")?;

    Ok(data)
}

fn load_from_file(path: &Path) -> anyhow::Result<StaticWebData> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let data: StaticWebData =
        serde_json::from_str(&contents).context("failed to parse JSON as StaticWebData")?;

    Ok(data)
}
