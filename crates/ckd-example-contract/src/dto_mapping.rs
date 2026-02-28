use attestation::{
    EventLog, TcbInfo,
    attestation::DstackAttestation,
    collateral::{Collateral, QuoteCollateralV3},
};
use contract_interface::types as dtos;

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

impl IntoContractType<DstackAttestation> for dtos::DstackAttestation {
    fn into_contract_type(self) -> DstackAttestation {
        let dtos::DstackAttestation {
            quote,
            collateral,
            tcb_info,
        } = self;

        DstackAttestation {
            quote: quote.into(),
            collateral: collateral.into_contract_type(),
            tcb_info: tcb_info.into_contract_type(),
        }
    }
}

impl IntoContractType<Collateral> for dtos::Collateral {
    fn into_contract_type(self) -> Collateral {
        let dtos::Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
        } = self;

        Collateral::from(QuoteCollateralV3 {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
        })
    }
}

impl IntoContractType<TcbInfo> for dtos::TcbInfo {
    fn into_contract_type(self) -> TcbInfo {
        let dtos::TcbInfo {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            os_image_hash,
            compose_hash,
            device_id,
            app_compose,
            event_log,
        } = self;

        let event_log = event_log
            .into_iter()
            .map(IntoContractType::into_contract_type)
            .collect();

        TcbInfo {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            os_image_hash,
            compose_hash,
            device_id,
            app_compose,
            event_log,
        }
    }
}

impl IntoContractType<EventLog> for dtos::EventLog {
    fn into_contract_type(self) -> EventLog {
        let dtos::EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = self;

        EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        }
    }
}
