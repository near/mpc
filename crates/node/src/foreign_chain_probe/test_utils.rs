//! Builders shared by the probe's test modules.

use foreign_chain_health_check::probe::{ProviderCounts, ProviderHealth, ProviderStatus};
use near_mpc_contract_interface::types as dtos;

use crate::metrics;

pub(super) fn row(
    chain: dtos::ForeignChain,
    provider: &str,
    status: ProviderStatus,
) -> ProviderHealth {
    ProviderHealth {
        chain,
        provider: dtos::ProviderId(provider.to_string()),
        status,
    }
}

pub(super) fn gauges(chain: &str) -> ProviderCounts {
    let count = |gauge: &prometheus::IntGaugeVec| {
        usize::try_from(gauge.with_label_values(&[chain]).get()).expect("a gauge is never negative")
    };
    ProviderCounts {
        configured: count(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED),
        healthy: count(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY),
    }
}
