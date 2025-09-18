use attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::Collateral,
    EventLog, TcbInfo,
};
use data_transfer_objects::dto_attestation::{
    DtoAttestation, DtoCollateral, DtoDstackAttestation, DtoEventLog, DtoMockAttestation,
    DtoTcbInfo,
};

pub(crate) trait ConvertDtoToContractType {
    type ContractType;

    fn into_contract_type(self) -> Self::ContractType;
}

impl ConvertDtoToContractType for DtoAttestation {
    type ContractType = Attestation;

    fn into_contract_type(self) -> Self::ContractType {
        match self {
            DtoAttestation::Dstack(dstack_attestation) => {
                Attestation::Dstack(dstack_attestation.into_contract_type())
            }
            DtoAttestation::Mock(mock_attestation) => {
                Attestation::Mock(mock_attestation.into_contract_type())
            }
        }
    }
}

impl ConvertDtoToContractType for DtoMockAttestation {
    type ContractType = MockAttestation;

    fn into_contract_type(self) -> Self::ContractType {
        match self {
            DtoMockAttestation::Valid => MockAttestation::Valid,
            DtoMockAttestation::Invalid => MockAttestation::Invalid,
            DtoMockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_time_stamp_seconds,
            } => MockAttestation::WithConstraints {
                mpc_docker_image_hash: mpc_docker_image_hash.map(Into::into),
                launcher_docker_compose_hash: launcher_docker_compose_hash.map(Into::into),
                expiry_time_stamp_seconds,
            },
        }
    }
}

impl ConvertDtoToContractType for DtoDstackAttestation {
    type ContractType = DstackAttestation;

    fn into_contract_type(self) -> Self::ContractType {
        let DtoDstackAttestation {
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

impl ConvertDtoToContractType for DtoCollateral {
    type ContractType = Collateral;

    fn into_contract_type(self) -> Self::ContractType {
        let DtoCollateral {
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

        Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
        }
    }
}

impl ConvertDtoToContractType for DtoTcbInfo {
    type ContractType = TcbInfo;

    fn into_contract_type(self) -> Self::ContractType {
        let DtoTcbInfo {
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
            .map(ConvertDtoToContractType::into_contract_type)
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

impl ConvertDtoToContractType for DtoEventLog {
    type ContractType = EventLog;

    fn into_contract_type(self) -> Self::ContractType {
        let DtoEventLog {
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
