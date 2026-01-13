use alloc::string::String;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use dstack_sdk_types::dstack::{EventLog as DstackEventLog, TcbInfo as DstackTcbInfo};
use serde::{Deserialize, Serialize};
use serde_with::{FromInto, hex::Hex, serde_as};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParsingError {
    #[error("wrong lenght: {0}")]
    WrongLength(usize),
    #[error("unexpected character: {0} {1}")]
    UnexpectedHexCharacter(char, usize),
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct EventLog {
    pub imr: u32,
    pub event_type: u32,
    pub digest: HexBytes<48>,
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
    BorshSerialize,
    BorshDeserialize,
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

impl<const N: usize> TryFrom<String> for HexBytes<N> {
    type Error = ParsingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let len = value.len();
        if len != 2 * N {
            Err(ParsingError::WrongLength(len))
        } else {
            let value = hex::decode(value).map_err(|err| match err {
                hex::FromHexError::InvalidHexCharacter { c, index } => {
                    ParsingError::UnexpectedHexCharacter(c, index)
                }
                hex::FromHexError::OddLength | hex::FromHexError::InvalidStringLength => {
                    ParsingError::WrongLength(len)
                }
            });
            match value {
                Ok(value) => {
                    let v: [u8; N] = value
                        .try_into()
                        .map_err(|_| ParsingError::WrongLength(len))?;
                    Ok(v.into())
                }
                Err(err) => Err(err),
            }
        }
    }
}

impl TryFrom<DstackTcbInfo> for TcbInfo {
    type Error = ParsingError;

    fn try_from(value: DstackTcbInfo) -> Result<Self, Self::Error> {
        let DstackTcbInfo {
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
        } = value;

        let event_log = event_log
            .into_iter()
            .map(|event| event.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let os_image_hash = if os_image_hash.is_empty() {
            None
        } else {
            Some(os_image_hash.try_into()?)
        };

        Ok(Self {
            mrtd: mrtd.try_into()?,
            rtmr0: rtmr0.try_into()?,
            rtmr1: rtmr1.try_into()?,
            rtmr2: rtmr2.try_into()?,
            rtmr3: rtmr3.try_into()?,
            os_image_hash,
            compose_hash: compose_hash.try_into()?,
            device_id: device_id.try_into()?,
            app_compose,
            event_log,
        })
    }
}

impl TryFrom<DstackEventLog> for EventLog {
    type Error = ParsingError;

    fn try_from(value: DstackEventLog) -> Result<Self, Self::Error> {
        let DstackEventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = value;

        Ok(Self {
            imr,
            event_type,
            digest: digest.try_into()?,
            event,
            event_payload,
        })
    }
}

impl<const N: usize> From<HexBytes<N>> for String {
    fn from(val: HexBytes<N>) -> Self {
        hex::encode(val.0)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    use super::*;
    use alloc::string::ToString;
    use rstest::rstest;
    use serde_json;

    #[test]
    fn TcbInfo__should_deserialize_from_real_test_data() {
        // Given
        const TCB_INFO_JSON: &str = include_str!("../assets/tcb_info.json");

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

    #[test]
    fn TcbInfo__should_succeed_tryfrom_DstackTcbInfo() {
        // Given
        const TCB_INFO_JSON: &str = include_str!("../assets/tcb_info.json");
        let dstack_tcb_info: DstackTcbInfo = serde_json::from_str(TCB_INFO_JSON).unwrap();

        // When
        let tcb_info: TcbInfo = dstack_tcb_info.try_into().unwrap();

        // Then
        assert_eq!(
            hex::encode(*tcb_info.rtmr0),
            "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46"
        )
    }

    #[test]
    fn TcbInfo__should_fail_tryfrom_DstackTcbInfo() {
        // Given
        const TCB_INFO_JSON: &str = include_str!("../assets/tcb_info.json");
        let mut dstack_tcb_info: DstackTcbInfo = serde_json::from_str(TCB_INFO_JSON).unwrap();
        // One extra char should make the conversion fail
        dstack_tcb_info.mrtd += "a";

        // When
        let result: Result<TcbInfo, _> = dstack_tcb_info.try_into();

        // Then
        assert!(result.is_err());
    }

    #[test]
    fn EventLog__should_succeed_tryfrom_DstackEventLog() {
        // Given
        const EVENT_LOG_JSON: &str = include_str!("../assets/event_log.json");
        let dstack_event_log: DstackEventLog = serde_json::from_str(EVENT_LOG_JSON).unwrap();

        // When
        let event_log: EventLog = dstack_event_log.try_into().unwrap();

        // Then
        assert_eq!(
            hex::encode(*event_log.digest),
            "8ae1e425351df7992c444586eff99d35af3b779aa2b0e981cb4b73bc5b279f2ade19b6a62a203fc3c3bbdaae80af596d"
        )
    }

    #[test]
    fn EventLog__should_fail_tryfrom_DstackEventLog() {
        // Given
        const EVENT_LOG_JSON: &str = include_str!("../assets/event_log.json");
        let mut dstack_event_log: DstackEventLog = serde_json::from_str(EVENT_LOG_JSON).unwrap();
        // One extra char should make the conversion fail
        dstack_event_log.digest += "a";

        // When
        let result: Result<EventLog, _> = dstack_event_log.try_into();

        // Then
        assert!(result.is_err());
    }

    #[test]
    fn HexBytes__should_succeed_tryfrom_String() {
        // Given
        let hex_str = "8ae1e425351df7992c444586eff99d35af3b779aa2b0e981cb4b73bc5b279f2ade19b6a62a203fc3c3bbdaae80af596d";

        // When
        let hex_bytes: HexBytes<48> = hex_str.to_string().try_into().unwrap();

        // Then
        assert_eq!(hex::encode(*hex_bytes), hex_str)
    }

    #[rstest]
    #[case("zae1e4", ParsingError::UnexpectedHexCharacter('z', 0))]
    #[case("8ae1e4a", ParsingError::WrongLength(7))]
    #[case("8ae1e4aa", ParsingError::WrongLength(8))]
    fn hexbytes_should_fail_tryfrom_string(
        #[case] hex_str: String,
        #[case] expected_error: ParsingError,
    ) {
        // Given hex_str

        // When
        let result: Result<HexBytes<3>, _> = hex_str.try_into();

        // Then
        assert_eq!(result.unwrap_err(), expected_error);
    }
}
