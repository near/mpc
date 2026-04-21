//! `asn1_der`-based [`X509Codec`] / [`ParsedCert`] implementation.
//!
//! Parses just enough of X.509 to satisfy the surface
//! [`dcap_qvl::config::ParsedCert`] requires: issuer DN extraction and
//! single-extension lookup. The full `x509-cert` decoder is not pulled in.
//!
//! ## Zero-copy
//!
//! [`Asn1DerParsedCert`] is generic over the input lifetime: the `tbs`
//! field is an `asn1_der::typed::Sequence<'a>` view that borrows directly
//! from the input DER bytes. No allocation, no cloning of the certificate
//! body.
//!
//! The audited [`dcap_qvl::x509::X509CertBackend`] cannot do this because
//! `x509_cert::Certificate` owns its parsed data. The GAT shape on
//! [`dcap_qvl::config::X509Codec::Parsed`] exists precisely so a
//! zero-copy backend like this one can be plugged in.

use alloc::{string::String, vec::Vec};
use anyhow::{anyhow, bail, Context, Result};
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

use dcap_qvl::config::{ParsedCert, X509Codec};

/// Context-tag byte for `[0] EXPLICIT` (X.509 `version` wrapper).
const TAG_CTX_0: u8 = 0xA0;
/// Context-tag byte for `[3] EXPLICIT` (X.509 `extensions` wrapper).
const TAG_CTX_3: u8 = 0xA3;

/// Tags asn1 DirectoryString variants we handle when stringifying issuer DN.
/// `0x13` = PrintableString, `0x0C` = UTF8String, `0x16` = IA5String.
const STRING_TAGS: &[u8] = &[0x13, 0x0C, 0x16];

/// Zero-sized factory implementing [`X509Codec`] on top of `asn1_der`.
///
/// Selected by [`crate::Asn1DerConfig`].
pub struct Asn1DerCertBackend;

/// Parsed certificate handle. Borrows from the input DER bytes for true
/// zero-copy reads.
#[derive(Copy, Clone)]
pub struct Asn1DerParsedCert<'a> {
    /// `tbsCertificate` SEQUENCE. All accessors walk this view.
    tbs: Sequence<'a>,
}

impl X509Codec for Asn1DerCertBackend {
    type Parsed<'a>
        = Asn1DerParsedCert<'a>
    where
        Self: 'a;

    fn from_der<'a>(cert_der: &'a [u8]) -> Result<Self::Parsed<'a>> {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        let cert: Sequence<'a> =
            Sequence::decode(cert_der).map_err(|e| anyhow!("Failed to decode certificate: {e}"))?;
        let tbs: Sequence<'a> = cert
            .get_as(0)
            .map_err(|e| anyhow!("Failed to decode tbsCertificate: {e}"))?;
        Ok(Asn1DerParsedCert { tbs })
    }
}

impl<'a> ParsedCert for Asn1DerParsedCert<'a> {
    /// Concatenate every printable RDN value in the issuer with `,` so the
    /// substring matches in `dcap_qvl::intel::pck_ca_with` (looking for
    /// e.g. `"Intel SGX PCK Processor CA"`) keep working unchanged.
    ///
    /// This is intentionally less structured than RFC 4514 — it is just
    /// enough to satisfy the substring contract documented on
    /// [`ParsedCert::issuer_dn`].
    fn issuer_dn(&self) -> Result<String> {
        // tbsCertificate ::= SEQUENCE {
        //     version         [0] EXPLICIT Version DEFAULT v1,
        //     serialNumber    CertificateSerialNumber,
        //     signature       AlgorithmIdentifier,
        //     issuer          Name,
        //     ...
        // }
        // If `version` is omitted (v1), `issuer` is at index 2; otherwise 3.
        let first = self
            .tbs
            .get(0)
            .map_err(|e| anyhow!("Empty tbsCertificate: {e}"))?;
        let issuer_idx: usize = if first.tag() == TAG_CTX_0 { 3 } else { 2 };

        let issuer: Sequence<'a> = self
            .tbs
            .get_as(issuer_idx)
            .map_err(|e| anyhow!("Failed to decode issuer: {e}"))?;

        // Name ::= SEQUENCE OF RelativeDistinguishedName
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
        let mut parts: Vec<&'a str> = Vec::new();
        for i in 0..issuer.len() {
            let rdn = issuer
                .get(i)
                .map_err(|e| anyhow!("Failed to get RDN: {e}"))?;
            let rdn_bytes = rdn.value();
            let mut pos: usize = 0;
            while pos < rdn_bytes.len() {
                let atv = DerObject::decode_at(rdn_bytes, pos)
                    .map_err(|e| anyhow!("Failed to decode ATV: {e}"))?;
                pos = pos
                    .checked_add(atv.raw().len())
                    .context("ATV offset overflow")?;
                let atv_seq = Sequence::load(atv)
                    .map_err(|e| anyhow!("Failed to load ATV as sequence: {e}"))?;
                let value = match atv_seq.get(1) {
                    Ok(v) if STRING_TAGS.contains(&v.tag()) => v,
                    // Skip OID-only or non-string values; downstream substring
                    // match doesn't depend on them.
                    _ => continue,
                };
                if let Ok(s) = core::str::from_utf8(value.value()) {
                    parts.push(s);
                }
            }
        }
        Ok(parts.join(","))
    }

    fn extension(&self, oid: &[u8]) -> Result<Option<Vec<u8>>> {
        // Walk tbsCertificate looking for the `[3] EXPLICIT` extensions
        // wrapper. Earlier optional fields (issuerUniqueID `[1]`,
        // subjectUniqueID `[2]`) come before it, so iterate.
        let mut extensions_inner: Option<&'a [u8]> = None;
        for i in 0..self.tbs.len() {
            let elem = self
                .tbs
                .get(i)
                .map_err(|e| anyhow!("Failed to get tbsCertificate element: {e}"))?;
            if elem.tag() == TAG_CTX_3 {
                extensions_inner = Some(elem.value());
                break;
            }
        }
        let extensions_inner = match extensions_inner {
            Some(b) => b,
            None => return Ok(None),
        };

        // Extensions ::= SEQUENCE OF Extension
        // Extension  ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
        let ext_seq = Sequence::decode(extensions_inner)
            .map_err(|e| anyhow!("Failed to decode extensions sequence: {e}"))?;

        let mut found: Option<Vec<u8>> = None;
        for i in 0..ext_seq.len() {
            let ext: Sequence<'a> = ext_seq
                .get_as(i)
                .map_err(|e| anyhow!("Failed to decode extension: {e}"))?;

            let oid_obj = ext
                .get(0)
                .map_err(|e| anyhow!("Missing extension OID: {e}"))?;
            if oid_obj.value() != oid {
                continue;
            }
            if found.is_some() {
                bail!("extension appears more than once");
            }

            // The OCTET STRING value is the last element of the SEQUENCE
            // (index 1 if `critical` absent, 2 if present).
            let value_idx = ext
                .len()
                .checked_sub(1)
                .context("Empty extension sequence")?;
            let value_obj = ext
                .get(value_idx)
                .map_err(|e| anyhow!("Missing extension value: {e}"))?;
            found = Some(value_obj.value().to_vec());
        }
        Ok(found)
    }
}
