use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::{FromInto, hex::Hex, serde_as};

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcbInfo {
    pub mrtd: HexBytes<48>,
    pub rtmr0: HexBytes<48>,
    pub rtmr1: HexBytes<48>,
    pub rtmr2: HexBytes<48>,
    pub rtmr3: HexBytes<48>,
    #[serde_as(as = "FromInto<HexBytesOrEmpty<32>>")]
    pub os_image_hash: Option<HexBytes<32>>,
    pub compose_hash: HexBytes<32>,
    pub device_id: HexBytes<32>,
    pub app_compose: String,
    pub event_log: Vec<EventLog>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    pub imr: u32,
    pub event_type: u32,
    #[serde_as(as = "Hex")]
    pub digest: [u8; 48],
    pub event: String,
    pub event_payload: String,
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Deref,
)]
#[serde(transparent)]
pub struct HexBytes<const N: usize>(#[serde_as(as = "Hex")] [u8; N]);

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HexBytesOrEmpty<const N: usize> {
    #[serde(untagged)]
    Some(HexBytes<N>),
    #[serde(untagged)]
    Empty(HexBytes<0>),
}

impl<const N: usize> From<HexBytesOrEmpty<N>> for Option<HexBytes<N>> {
    fn from(value: HexBytesOrEmpty<N>) -> Self {
        match value {
            HexBytesOrEmpty::Some(hex_bytes) => Some(hex_bytes),
            HexBytesOrEmpty::Empty(_) => None,
        }
    }
}

impl<const N: usize> From<Option<HexBytes<N>>> for HexBytesOrEmpty<N> {
    fn from(value: Option<HexBytes<N>>) -> Self {
        match value {
            Some(hex_bytes) => HexBytesOrEmpty::Some(hex_bytes),
            None => HexBytesOrEmpty::Empty(HexBytes([])),
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn TcbInfo__should_deserialize_from_real_test_data() {
        // Given
        const TCB_INFO_JSON: &str = include_str!("../../test-utils/assets/tcb_info.json");

        // When
        let tcb_info: TcbInfo = serde_json::from_str(TCB_INFO_JSON).unwrap();

        // Then
        assert_eq!(
            hex::encode(*tcb_info.rtmr0),
            "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46"
        )
    }

    #[test]
    fn TcbInfo__should_fail_deserialization_with_invalid_hex_length() {
        // Given
        let json = r#"{
            "mrtd": "invalid_length",
            "rtmr0": "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
            "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
            "rtmr2": "dbf4924c07f5066f3dc6859844184344306aa3263817153dcaee85af97d23e0c0b96efe0731d8865a8747e51b9e351ac",
            "rtmr3": "e0d4a068296ebdfc4c9cbf4777663c65c0da4405b8380f28e344f1fab52490264944ff8ccfde112b85eb1d997785e2ac",
            "compose_hash": "3efecc42bdef4cb42fa354e9b84fe00e9d82b5397a739e0b03188ab80d72ed81",
            "device_id": "7a82191bd4dedb9d716e3aa422963cf1009f36e3068404a0322feca1ce517dc9",
            "app_compose": "test_compose",
            "event_log": []
        }"#;

        // When
        let result: Result<TcbInfo, _> = serde_json::from_str(json);

        // Then
        assert!(result.is_err());
    }
}
