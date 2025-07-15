use dcap_qvl::quote::Quote as DcapQuote;
use derive_more::{Deref, From};

/// TEE Remote Attestation Quote that proves the participant's identity.
#[derive(From, Deref)]
pub struct Quote(DcapQuote);
