use crate::types::{PayloadBytesError, Update};

pub(super) fn update_payload_bytes(update: &Update) -> Result<u128, PayloadBytesError> {
    let bytes = match update {
        Update::Code(code) => code.len(),
        Update::Config(config) => serde_json::to_vec(config)?.len(),
    };
    u128::try_from(bytes).map_err(|_| PayloadBytesError::Overflow)
}
