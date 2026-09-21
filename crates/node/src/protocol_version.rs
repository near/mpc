use derive_more::Display;
use num_enum::{FromPrimitive, IntoPrimitive};

/// the current protocol version
pub const CURRENT_PROTOCOL_VERSION: NetworkProtocolVersion = NetworkProtocolVersion::Jan2026;

/// This must be extended every time we introduce an incompatible protocol
/// change.
#[derive(Debug, Copy, Clone, IntoPrimitive, FromPrimitive, PartialEq, Display)]
#[repr(u32)]
pub enum NetworkProtocolVersion {
    #[num_enum(alternatives = [1..7])]
    Unsupported = 0,
    Dec2025 = 7,
    Jan2026 = 8,
    #[num_enum(catch_all)]
    Unknown(u32),
}

impl NetworkProtocolVersion {
    /// Whether a peer advertising `self` can be assumed to handle a feature introduced in
    /// `required`. Comparison is by wire value, so a peer on a version newer than this binary
    /// recognizes also passes; whether it is in fact still compatible is that peer's call to
    /// make, not ours. This is not a general backwards-compatibility claim: support for old
    /// versions is dropped by folding them into [`NetworkProtocolVersion::Unsupported`], which
    /// fails every check.
    pub fn supports(self, required: NetworkProtocolVersion) -> bool {
        u32::from(self) >= u32::from(required)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::NetworkProtocolVersion;
    use rstest::rstest;

    #[rstest]
    #[case::same_version(NetworkProtocolVersion::Jan2026, NetworkProtocolVersion::Jan2026, true)]
    #[case::newer_version(NetworkProtocolVersion::Jan2026, NetworkProtocolVersion::Dec2025, true)]
    #[case::older_version(
        NetworkProtocolVersion::Dec2025,
        NetworkProtocolVersion::Jan2026,
        false
    )]
    #[case::future_version(
        NetworkProtocolVersion::Unknown(42),
        NetworkProtocolVersion::Jan2026,
        true
    )]
    #[case::unsupported_version(
        NetworkProtocolVersion::Unsupported,
        NetworkProtocolVersion::Dec2025,
        false
    )]
    fn communication_protocols__should_compare_by_wire_value_including_unknown(
        #[case] advertised: NetworkProtocolVersion,
        #[case] required: NetworkProtocolVersion,
        #[case] supported: bool,
    ) {
        // When
        let result = advertised.supports(required);

        // Then
        assert_eq!(result, supported);
    }
}
