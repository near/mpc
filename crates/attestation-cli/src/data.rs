use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use node_types::http_server::StaticWebData;

use crate::cli::Cli;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn load(cli: &Cli) -> anyhow::Result<StaticWebData> {
    match (&cli.url, &cli.file) {
        (Some(url), None) => fetch(url).await,
        (None, Some(path)) => read(path),
        (None, None) => bail!("either --url or --file must be provided"),
        (Some(_), Some(_)) => bail!("--url and --file are mutually exclusive"),
    }
}

async fn fetch(url: &url::Url) -> anyhow::Result<StaticWebData> {
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

fn read(path: &Path) -> anyhow::Result<StaticWebData> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(serde_json::from_reader(file)?)
}
