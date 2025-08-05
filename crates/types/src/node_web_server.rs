use mpc_contract::tee::tee_participant::TeeParticipantInfo;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct StaticWebData {
    pub near_signer_public_key: near_crypto::PublicKey,
    pub near_p2p_public_key: near_crypto::PublicKey,
    pub near_responder_public_keys: Vec<near_crypto::PublicKey>,
    pub tee_participant_info: Option<TeeParticipantInfo>,
}
