mod consts;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use mpc_primitives::hash::NodeImageHash;
use serde::Deserialize;

use consts::{HUB_BASE, MAX_PAGES, MPC_IMAGE_REPO, PAGE_SIZE, TIMEOUT_SECS};

#[derive(Deserialize)]
struct TagsPage {
    results: Vec<TagEntry>,
    next: Option<String>,
}

#[derive(Deserialize)]
struct TagEntry {
    name: String,
    digest: Option<String>,
    #[serde(default)]
    images: Vec<ImageEntry>,
}

#[derive(Deserialize)]
struct ImageEntry {
    digest: Option<String>,
}

/// Best-effort fetch of every published `{manifest_digest -> tag}` pair for the
/// MPC node image. Returns an empty map on any failure (timeout, non-2xx, parse
/// error) and prints a single warning line to stderr.
pub async fn fetch_mpc_image_versions() -> BTreeMap<NodeImageHash, String> {
    match fetch_inner(MPC_IMAGE_REPO).await {
        Ok(map) => map,
        Err(e) => {
            eprintln!("warning: Docker Hub version lookup failed: {e:#}");
            BTreeMap::new()
        }
    }
}

async fn fetch_inner(repo: &str) -> Result<BTreeMap<NodeImageHash, String>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        .build()?;
    let mut out = BTreeMap::new();
    let mut url = format!("{HUB_BASE}/repositories/{repo}/tags?page_size={PAGE_SIZE}");
    for _ in 0..MAX_PAGES {
        let page: TagsPage = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decoding tags page")?;
        for tag in page.results {
            let digests = tag
                .digest
                .iter()
                .chain(tag.images.iter().filter_map(|i| i.digest.as_ref()));
            for digest in digests {
                if let Some(hash) = parse_sha256(digest) {
                    out.entry(hash).or_insert_with(|| tag.name.clone());
                }
            }
        }
        match page.next {
            Some(next) => url = next,
            None => break,
        }
    }
    Ok(out)
}

fn parse_sha256(s: &str) -> Option<NodeImageHash> {
    let hex_str = s.strip_prefix("sha256:")?;
    let bytes: [u8; 32] = hex::decode(hex_str).ok()?.try_into().ok()?;
    Some(NodeImageHash::from(bytes))
}
