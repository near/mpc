use num_enum::{IntoPrimitive, TryFromPrimitive};

/// the current protocol version
pub const CURRENT_PROTOCOL_VERSION: KnownMpcProtocols = KnownMpcProtocols::Jan2026;

/// This must be extended every time we introduce an incompatible protocol
/// change.
#[derive(Debug, Copy, Clone, IntoPrimitive, TryFromPrimitive, PartialEq)]
#[repr(u32)]
pub enum KnownMpcProtocols {
    #[num_enum(alternatives = [1..7])]
    Unsupported = 0,
    Dec2025 = 7,
    Jan2026 = 8,
}
