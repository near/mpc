use derive_more::Display;
use num_enum::{FromPrimitive, IntoPrimitive};

/// the current protocol version
pub const CURRENT_PROTOCOL_VERSION: NetworkProtocolVersion = NetworkProtocolVersion::Sep2026;

/// This must be extended every time we introduce an incompatible protocol
/// change.
#[derive(Debug, Copy, Clone, IntoPrimitive, FromPrimitive, PartialEq, Display)]
#[repr(u32)]
pub enum NetworkProtocolVersion {
    #[num_enum(alternatives = [1..7])]
    Unsupported = 0,
    Dec2025 = 7,
    Jan2026 = 8,
    /// Adds [`EcdsaTaskId::OnlinePresignSignature`](crate::network::wire_format::EcdsaTaskId::OnlinePresignSignature).
    Sep2026 = 9,
    #[num_enum(catch_all)]
    Unknown(u32),
}

impl NetworkProtocolVersion {
    /// Whether a peer advertising `self` supports a feature introduced in `required`.
    /// Unknown higher versions pass: keeping up with `required` is the newer peer's
    /// responsibility. For old versions,  we move them into
    /// [`NetworkProtocolVersion::Unsupported`] and reject directly.
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
    fn network_protocol_version__should_compare_by_wire_value_including_unknown(
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
