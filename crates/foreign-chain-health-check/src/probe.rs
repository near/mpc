//! Asks every configured RPC provider which network it serves and compares the answer against the
//! operator's `expected_network_fingerprint`.

use foreign_chain_inspector::{
    BuildInspectors, FanOut, ForeignChainInspectionError, NetworkFingerprint, ProviderFailure,
};
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

mod report;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;

pub use report::{ProbeReport, ProviderCounts, ProviderHealth, ProviderStatus};

/// Probe every configured provider concurrently.
///
/// Each provider is tried up to `max_retries` times, `timeout_sec` per try, and only for as long as
/// the failures stay transient. This returns within the largest configured `timeout_sec *
/// max_retries`, plus the [`foreign_chain_inspector::RETRY_BACKOFF`] between tries.
pub async fn probe_all_providers<InspectorFactory>(
    config: &ForeignChainsConfig,
    inspectors: &InspectorFactory,
) -> ProbeReport
where
    InspectorFactory: BuildInspectors,
{
    let probe_attempts = config.into_iter().map(|(chain, chain_config)| {
        let timeout = chain_config.timeout_duration();
        async move {
            probe_chain(chain, chain_config, |provider| {
                inspectors.build(chain, provider, timeout)
            })
            .await
        }
    });

    futures::future::join_all(probe_attempts)
        .await
        .concat()
        .into()
}

async fn probe_chain<I>(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    build_new_inspector: impl Fn(&ForeignChainProviderConfig) -> anyhow::Result<Option<I>>,
) -> Vec<ProviderHealth>
where
    I: foreign_chain_inspector::ChainInspector,
{
    let mut inspectors = Vec::new();
    let mut rows = Vec::new();
    for (name, provider) in config.providers.iter() {
        let provider_id = ProviderId(name.as_str().to_owned());
        match build_new_inspector(provider) {
            // Inspector not implemented for the chain
            Ok(None) => return rows_of(chain, config, ProviderStatus::ProbeNotImplemented),
            Ok(Some(inspector)) => inspectors.push((provider_id, inspector)),
            Err(error) => rows.push(ProviderHealth {
                chain,
                provider: provider_id,
                status: setup_failure(&error),
            }),
        }
    }

    let Some(expected) = &config.expected_network_fingerprint else {
        return rows_of(chain, config, ProviderStatus::MissingExpectedFingerprint);
    };

    let Ok(inspectors) = NonEmptyVec::try_from(inspectors) else {
        return rows;
    };
    // Any of the chain's inspectors normalizes the same way; the first one that built is enough.
    let (_, inspector) = inspectors.first();
    let expected = inspector.canonical_fingerprint(expected);

    let fingerprints = FanOut::new(inspectors)
        .network_fingerprints(config.timeout_duration(), config.max_retries)
        .await;
    for (provider, reported) in fingerprints {
        rows.push(ProviderHealth {
            chain,
            provider,
            status: classify(&expected, reported),
        });
    }
    rows
}

/// [`ProviderStatus`] carries no error text, so the one actionable cause gets its own variant. Only
/// a token read from the environment can fail to resolve; a [`std::env::VarError`] identifies it.
fn setup_failure(error: &anyhow::Error) -> ProviderStatus {
    if error.chain().any(|cause| cause.is::<std::env::VarError>()) {
        ProviderStatus::AuthTokenUnresolved
    } else {
        ProviderStatus::ClientSetupFailed
    }
}

fn rows_of(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    status: ProviderStatus,
) -> Vec<ProviderHealth> {
    config
        .providers
        .keys()
        .map(|name| ProviderHealth {
            chain,
            provider: ProviderId(name.as_str().to_owned()),
            status: status.clone(),
        })
        .collect()
}

fn classify(
    expected: &NetworkFingerprint,
    reported: Result<NetworkFingerprint, ForeignChainInspectionError>,
) -> ProviderStatus {
    match reported {
        Ok(observed) if &observed == expected => ProviderStatus::Healthy,
        Ok(observed) => ProviderStatus::WrongNetwork {
            expected: expected.clone(),
            observed,
        },
        Err(error) => match error.provider_failure() {
            Some(ProviderFailure::Unreachable) => ProviderStatus::Unreachable,
            Some(ProviderFailure::Rejected) => ProviderStatus::RequestRejected,
            Some(ProviderFailure::TimedOut) => ProviderStatus::TimedOut,
            Some(ProviderFailure::Malformed) => ProviderStatus::MalformedResponse,
            // Probing does not inspect transactions, so an answer about transaction state
            // means an impl answered outside its contract.
            None => ProviderStatus::MalformedResponse,
        },
    }
}
