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
use crate::http_client::HttpClient;
use crate::hyperevm::inspector::HyperEvm;
use crate::polygon::inspector::Polygon;
use crate::starknet::inspector::StarknetInspector;
use crate::sui::inspector::SuiInspector;
use crate::svm::inspector::{Fogo, Solana, SvmInspector};
use crate::{ForeignChainInspectionError, NetworkFingerprint, NetworkFingerprintInspector};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;

#[derive(Clone)]
pub enum RpcInspector {
    Abstract(EvmInspector<HttpClient, Abstract>),
    Adi(EvmInspector<HttpClient, Adi>),
    Aptos(AptosInspector<ReqwestAptosClient>),
    Arbitrum(EvmInspector<HttpClient, Arbitrum>),
    Avalanche(EvmInspector<HttpClient, Avalanche>),
    Base(EvmInspector<HttpClient, Base>),
    Bitcoin(BitcoinInspector<HttpClient>),
    Bnb(EvmInspector<HttpClient, Bnb>),
    Ethereum(EvmInspector<HttpClient, Ethereum>),
    Fogo(SvmInspector<HttpClient, Fogo>),
    HyperEvm(EvmInspector<HttpClient, HyperEvm>),
    Polygon(EvmInspector<HttpClient, Polygon>),
    Solana(SvmInspector<HttpClient, Solana>),
    Starknet(StarknetInspector<HttpClient>),
    Sui(SuiInspector<GrpcSuiClient>),
}

impl NetworkFingerprintInspector for RpcInspector {
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
            Self::Fogo(inspector) => inspector.network_fingerprint().await,
            Self::HyperEvm(inspector) => inspector.network_fingerprint().await,
            Self::Polygon(inspector) => inspector.network_fingerprint().await,
            Self::Solana(inspector) => inspector.network_fingerprint().await,
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
            Self::Fogo(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::HyperEvm(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Polygon(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Solana(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Starknet(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Sui(inspector) => inspector.canonical_fingerprint(fingerprint),
        }
    }
}
