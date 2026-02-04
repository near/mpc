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
