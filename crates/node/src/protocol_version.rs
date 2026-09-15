use derive_more::Display;
use num_enum::{FromPrimitive, IntoPrimitive};

/// the current protocol version
pub const CURRENT_PROTOCOL_VERSION: CommunicationProtocols = CommunicationProtocols::Jan2026;

/// This must be extended every time we introduce an incompatible protocol
/// change.
#[derive(Debug, Copy, Clone, IntoPrimitive, FromPrimitive, PartialEq, Display)]
#[repr(u32)]
pub enum CommunicationProtocols {
    #[num_enum(alternatives = [1..7])]
    Unsupported = 0,
    Dec2025 = 7,
    Jan2026 = 8,
    #[num_enum(catch_all)]
    Unknown(u32),
}

impl CommunicationProtocols {
    /// Whether a peer advertising `self` understands everything introduced up to `required`.
    /// Versions are compared by wire value, so a peer on a future version passes.
    pub fn supports(self, required: CommunicationProtocols) -> bool {
        u32::from(self) >= u32::from(required)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::CommunicationProtocols;
    use rstest::rstest;

    #[rstest]
    #[case::same_version(CommunicationProtocols::Jan2026, CommunicationProtocols::Jan2026, true)]
    #[case::newer_version(CommunicationProtocols::Jan2026, CommunicationProtocols::Dec2025, true)]
    #[case::older_version(
        CommunicationProtocols::Dec2025,
        CommunicationProtocols::Jan2026,
        false
    )]
    #[case::future_version(
        CommunicationProtocols::Unknown(42),
        CommunicationProtocols::Jan2026,
        true
    )]
    #[case::unsupported_version(
        CommunicationProtocols::Unsupported,
        CommunicationProtocols::Dec2025,
        false
    )]
    fn communication_protocols__should_compare_by_wire_value_including_unknown(
        #[case] advertised: CommunicationProtocols,
        #[case] required: CommunicationProtocols,
        #[case] supported: bool,
    ) {
        // When
        let result = advertised.supports(required);

        // Then
        assert_eq!(result, supported);
    }
}
