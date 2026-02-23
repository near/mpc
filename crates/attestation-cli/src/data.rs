use std::path::Path;

use anyhow::{Context, bail};
use node_types::http_server::StaticWebData;

use crate::cli::VerifyArgs;

pub async fn load_static_web_data(args: &VerifyArgs) -> anyhow::Result<StaticWebData> {
    match (&args.url, &args.file) {
        (Some(url), None) => fetch_from_url(url).await,
        (None, Some(path)) => load_from_file(path),
        (None, None) => bail!("either --url or --file must be provided"),
        (Some(_), Some(_)) => bail!("--url and --file are mutually exclusive"),
    }
}

async fn fetch_from_url(url: &str) -> anyhow::Result<StaticWebData> {
    let response = reqwest::get(url)
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
