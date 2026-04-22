//! `asn1_der`-based [`EcdsaSigEncoder`] implementation.
//!
//! ECDSA P-256 signatures inside DCAP quotes are 64-byte raw `r ‖ s`
//! payloads. webpki's signature verifier expects them DER-encoded as
//! `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 5480).
//!
//! `asn1_der::typed::Integer::write` already does the DER integer dance:
//! strip leading zero bytes, prepend `0x00` when the high bit would
//! otherwise make the value negative, and emit `02 01 00` for zero. We
//! call it twice (once per component) into a temporary buffer, then wrap
//! the concatenation in a SEQUENCE header.

use anyhow::{Context, Result};
use asn1_der::{
    DerObject, VecBacking,
    typed::{DerTypeView, Integer, Sequence},
};

use dcap_qvl::config::EcdsaSigEncoder;

/// Zero-sized [`EcdsaSigEncoder`] backed by `asn1_der`. Selected by
/// [`crate::Asn1DerConfig`].
pub struct Asn1DerSigEncoder;

impl EcdsaSigEncoder for Asn1DerSigEncoder {
    fn encode_ecdsa_sig(r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
        // Worst case per integer: payload + 1-byte sign pad + 2-byte
        // tag-length header. SEQUENCE wrapper adds another 4 bytes of
        // overhead.  Pre-sizing is purely a perf hint; `Vec` will grow
        // if asn1_der ever needs more.
        let payload_cap = r
            .len()
            .checked_add(s.len())
            .and_then(|n| n.checked_add(6))
            .context("ecdsa-sig payload size overflow")?;
        let total_cap = payload_cap
            .checked_add(4)
            .context("ecdsa-sig total size overflow")?;

        let mut payload = Vec::with_capacity(payload_cap);
        Integer::write(r, false, &mut VecBacking(&mut payload))
            .context("failed to encode r INTEGER")?;
        Integer::write(s, false, &mut VecBacking(&mut payload))
            .context("failed to encode s INTEGER")?;

        let mut out = Vec::with_capacity(total_cap);
        DerObject::write(
            <Sequence as DerTypeView>::TAG,
            payload.len(),
            &mut payload.iter(),
            &mut VecBacking(&mut out),
        )
        .context("failed to encode ECDSA sig SEQUENCE")?;
        Ok(out)
    }
}
