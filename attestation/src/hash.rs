use alloc::string::String;
use core::marker::PhantomData;

pub struct Hash32<T> {
    pub bytes: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T> Hash32<T> {
    pub fn as_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

impl<T> From<[u8; 32]> for Hash32<T> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

// Marker types
pub struct Image;
pub struct Compose;

/// Hash of an MPC Docker image running in the TEE environment. Used as a proposal for a new TEE
/// code hash to add to the whitelist, together with the TEE quote (which includes the RTMR3
/// measurement and more).
pub type MpcDockerImageHash = Hash32<Image>;

/// Hash of the launcher's Docker Compose file used to run the MPC node in the TEE environment. It
/// is computed from the launcher's Docker Compose template populated with the MPC node's Docker
/// image hash.
pub type LauncherDockerComposeHash = Hash32<Compose>;
