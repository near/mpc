//! One type holding any chain's inspector.

use crate::abstract_chain::inspector::Abstract;
use crate::adi::inspector::Adi;
use crate::aptos::inspector::AptosInspector;
use crate::arbitrum::inspector::Arbitrum;
use crate::avalanche::inspector::Avalanche;
use crate::base::inspector::Base;
use crate::bitcoin::inspector::BitcoinInspector;
use crate::bnb::inspector::Bnb;
use crate::ethereum::inspector::Ethereum;
use crate::evm::inspector::EvmInspector;
use crate::hyperevm::inspector::HyperEvm;
use crate::polygon::inspector::Polygon;
use crate::starknet::inspector::StarknetInspector;
use crate::sui::inspector::SuiInspector;
use crate::{ForeignChainInspectionError, NetworkFingerprint, NetworkFingerprintInspector};
use foreign_chain_rpc_interfaces::aptos::AptosRpcClient;
use foreign_chain_rpc_interfaces::sui::SuiRpcClient;
use jsonrpsee::core::client::ClientT;

/// [`NetworkFingerprintInspector`] is not dyn compatible, so a caller that spans chains needs an
/// enum rather than a trait object.
#[derive(Clone)]
pub enum RpcInspector<JsonRpc, Aptos, Sui> {
    Abstract(EvmInspector<JsonRpc, Abstract>),
    Adi(EvmInspector<JsonRpc, Adi>),
    Aptos(AptosInspector<Aptos>),
    Arbitrum(EvmInspector<JsonRpc, Arbitrum>),
    Avalanche(EvmInspector<JsonRpc, Avalanche>),
    Base(EvmInspector<JsonRpc, Base>),
    Bitcoin(BitcoinInspector<JsonRpc>),
    Bnb(EvmInspector<JsonRpc, Bnb>),
    Ethereum(EvmInspector<JsonRpc, Ethereum>),
    HyperEvm(EvmInspector<JsonRpc, HyperEvm>),
    Polygon(EvmInspector<JsonRpc, Polygon>),
    Starknet(StarknetInspector<JsonRpc>),
    Sui(SuiInspector<Sui>),
}

impl<JsonRpc, Aptos, Sui> NetworkFingerprintInspector for RpcInspector<JsonRpc, Aptos, Sui>
where
    JsonRpc: ClientT + Send + Sync,
    Aptos: AptosRpcClient + Send + Sync,
    Sui: SuiRpcClient + Send + Sync,
{
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        match self {
            Self::Abstract(inspector) => inspector.network_fingerprint().await,
            Self::Adi(inspector) => inspector.network_fingerprint().await,
            Self::Aptos(inspector) => inspector.network_fingerprint().await,
            Self::Arbitrum(inspector) => inspector.network_fingerprint().await,
            Self::Avalanche(inspector) => inspector.network_fingerprint().await,
            Self::Base(inspector) => inspector.network_fingerprint().await,
            Self::Bitcoin(inspector) => inspector.network_fingerprint().await,
            Self::Bnb(inspector) => inspector.network_fingerprint().await,
            Self::Ethereum(inspector) => inspector.network_fingerprint().await,
            Self::HyperEvm(inspector) => inspector.network_fingerprint().await,
            Self::Polygon(inspector) => inspector.network_fingerprint().await,
            Self::Starknet(inspector) => inspector.network_fingerprint().await,
            Self::Sui(inspector) => inspector.network_fingerprint().await,
        }
    }

    fn canonical_fingerprint(&self, fingerprint: &str) -> NetworkFingerprint {
        match self {
            Self::Abstract(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Adi(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Aptos(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Arbitrum(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Avalanche(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Base(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Bitcoin(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Bnb(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Ethereum(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::HyperEvm(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Polygon(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Starknet(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Sui(inspector) => inspector.canonical_fingerprint(fingerprint),
        }
    }
}
