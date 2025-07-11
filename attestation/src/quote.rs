use dcap_qvl::quote::Quote as DcapQuote;

/// TEE Remote Attestation Quote that proves the participant's identity.
pub(crate) struct Quote(pub(crate) DcapQuote);

impl Quote {
    pub fn new(quote: DcapQuote) -> Self {
        Self(quote)
    }

    pub fn get(&self) -> &DcapQuote {
        &self.0
    }
}
