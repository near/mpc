/// Supplemental data for the TEE quote, including Intel certificates to verify it came from
/// genuine Intel hardware, along with details about the Trusted Computing Base (TCB)
/// versioning, status, and other relevant info.
pub(crate) struct Collateral(String);

impl Collateral {
    pub fn new(collateral: String) -> Self {
        Self(collateral)
    }

    pub fn get(&self) -> &str {
        &self.0
    }
}
