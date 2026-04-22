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

use anyhow::{Context, Result, bail};
use asn1_der::{
    DerObject,
    typed::{DerDecodable, DerTypeView, Sequence},
};

use dcap_qvl::config::{ParsedCert, X509Codec};

/// Context-tag byte for `[0] EXPLICIT` (X.509 `version` wrapper).
const TAG_CTX_0: u8 = 0xA0;
/// Context-tag byte for `[3] EXPLICIT` (X.509 `extensions` wrapper).
const TAG_CTX_3: u8 = 0xA3;
/// DER tag for `OBJECT IDENTIFIER`, the required type of `Extension.extnID`.
const TAG_OID: u8 = 0x06;
/// DER tag for `OCTET STRING`, the required type of `Extension.extnValue`.
const TAG_OCTET_STRING: u8 = 0x04;
/// DER tag for `BOOLEAN`, the required type of `Extension.critical` when present.
const TAG_BOOLEAN: u8 = 0x01;

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
    type Parsed<'a> = Asn1DerParsedCert<'a>;

    fn from_der(cert_der: &[u8]) -> Result<Self::Parsed<'_>> {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        let cert = Sequence::decode(cert_der).context("failed to decode certificate")?;
        // `asn1_der::DerObject::decode` accepts trailing bytes after the
        // outer SEQUENCE; the audited `x509-cert` backend does not. Match
        // that behaviour here so we stay a strict drop-in replacement.
        if cert.object().raw().len() != cert_der.len() {
            bail!("trailing bytes after outer Certificate SEQUENCE");
        }
        let tbs = cert
            .get_as::<Sequence<'_>>(0)
            .context("failed to decode tbsCertificate")?;
        Ok(Asn1DerParsedCert { tbs })
    }
}

impl ParsedCert for Asn1DerParsedCert<'_> {
    /// Concatenate every printable RDN value in the issuer with `,` so the
    /// substring matches in `dcap_qvl::intel::pck_ca_with` (looking for
    /// e.g. `"Intel SGX PCK Processor CA"`) keep working unchanged.
    ///
    /// This is intentionally less structured than RFC 4514 — it is just
    /// enough to satisfy the substring contract documented on
    /// [`ParsedCert::issuer_dn`].
    ///
    /// # Warning
    ///
    /// The output is **not** RFC 4514 and diverges from
    /// [`dcap_qvl::x509::X509CertParsed::issuer_dn`] in several visible ways:
    ///
    /// - RDNs are concatenated in **forward DER order**. RFC 4514 (and the
    ///   audited default) emits them **reversed**.
    /// - Attribute-type labels (`CN=`, `O=`, `C=`, …) are stripped.
    /// - Special characters (`,`, `+`, `;`, `<`, `>`, `"`, `\\`, leading `#`,
    ///   control characters) are **not escaped** — raw bytes pass through.
    /// - Multi-valued RDNs are flattened into the same comma-joined list;
    ///   there is no `+` separator.
    /// - Only `PrintableString` (0x13), `UTF8String` (0x0C) and `IA5String`
    ///   (0x16) are extracted; other `DirectoryString` variants
    ///   (`TeletexString`, `BMPString`, `UniversalString`, …) are silently
    ///   dropped.
    ///
    /// These differences do not affect the two substring checks the rest of
    /// `dcap-qvl` performs today (`"Intel SGX PCK Processor CA"` /
    /// `"Intel SGX PCK Platform CA"`, both covered by
    /// `parsed_cert_matches_default_on_sample_corpus` in the conformance
    /// suite). Any caller that adds a **new** `.contains(needle)` check on
    /// the issuer DN MUST also extend that conformance test with the new
    /// needle, otherwise the custom and audited backends may silently
    /// disagree on Intel-issued certs.
    fn issuer_dn(&self) -> Result<String> {
        // tbsCertificate ::= SEQUENCE {
        //     version         [0] EXPLICIT Version DEFAULT v1,
        //     serialNumber    CertificateSerialNumber,
        //     signature       AlgorithmIdentifier,
        //     issuer          Name,
        //     ...
        // }
        // If `version` is omitted (v1), `issuer` is at index 2; otherwise 3.
        let first = self.tbs.get(0).context("empty tbsCertificate")?;
        let issuer_idx = if first.tag() == TAG_CTX_0 { 3 } else { 2 };

        let issuer = self
            .tbs
            .get_as::<Sequence<'_>>(issuer_idx)
            .context("failed to decode issuer")?;

        // Name ::= SEQUENCE OF RelativeDistinguishedName
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
        let mut parts = Vec::new();
        for i in 0..issuer.len() {
            let rdn = issuer.get(i).context("failed to get RDN")?;
            let rdn_bytes = rdn.value();
            let mut pos = 0;
            while pos < rdn_bytes.len() {
                let atv = DerObject::decode_at(rdn_bytes, pos).context("failed to decode ATV")?;
                pos = pos
                    .checked_add(atv.raw().len())
                    .context("ATV offset overflow")?;
                let atv_seq = Sequence::load(atv).context("failed to load ATV as sequence")?;
                let value = match atv_seq.get(1) {
                    // `0x13` = PrintableString, `0x0C` = UTF8String, `0x16` = IA5String.
                    Ok(v) if matches!(v.tag(), 0x13 | 0x0C | 0x16) => v,
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
        let mut extensions_inner = None;
        for i in 0..self.tbs.len() {
            let elem = self
                .tbs
                .get(i)
                .context("failed to get tbsCertificate element")?;
            if elem.tag() == TAG_CTX_3 {
                extensions_inner = Some(elem.value());
                break;
            }
        }
        let Some(extensions_inner) = extensions_inner else {
            return Ok(None);
        };

        // Extensions ::= SEQUENCE OF Extension
        // Extension  ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
        let ext_seq =
            Sequence::decode(extensions_inner).context("failed to decode extensions sequence")?;

        let mut found: Option<Vec<u8>> = None;
        for i in 0..ext_seq.len() {
            let ext = ext_seq
                .get_as::<Sequence<'_>>(i)
                .context("failed to decode extension")?;

            let oid_obj = ext.get(0).context("missing extension OID")?;
            // `Extension.extnID` is specified as OBJECT IDENTIFIER
            // (tag 0x06). The audited `x509-cert` backend enforces this
            // via its typed `extn_id: ObjectIdentifier` decode; we do it
            // explicitly so an extension shaped e.g.
            // `SEQUENCE { OCTET_STRING <sgx-oid-bytes>, ... }` can never
            // byte-match the query OID and leak an unintended value.
            let extn_id_tag = oid_obj.tag();
            if extn_id_tag != TAG_OID {
                bail!("extension extnID is not an OBJECT IDENTIFIER (tag 0x{extn_id_tag:02X})");
            }
            if oid_obj.value() != oid {
                continue;
            }
            if found.is_some() {
                bail!("extension appears more than once");
            }

            // Extension must carry { oid, extnValue } or { oid, critical,
            // extnValue }; reject other shapes rather than guessing. A cert
            // that is missing extnValue (e.g. only { oid, critical }) would
            // otherwise hand back the BOOLEAN bytes as if they were the
            // extension value.
            let ext_len = ext.len();
            if !(2..=3).contains(&ext_len) {
                bail!("extension sequence has unexpected shape (len {ext_len})");
            }
            if ext_len == 3 {
                // `Extension.critical` is specified as BOOLEAN (tag 0x01).
                // The audited `x509-cert` backend enforces this via its
                // typed `critical: bool` decode; we check explicitly so a
                // cert shaped e.g. `SEQUENCE { OID, <junk>, OCTET_STRING }`
                // cannot byte-match and leak the OCTET_STRING as the
                // extension value.
                let critical_obj = ext.get(1).context("missing extension critical flag")?;
                let critical_tag = critical_obj.tag();
                if critical_tag != TAG_BOOLEAN {
                    bail!("extension critical is not a BOOLEAN (tag 0x{critical_tag:02X})");
                }
            }
            let value_obj = ext.get(ext_len - 1).context("missing extension value")?;
            let value_tag = value_obj.tag();
            if value_tag != TAG_OCTET_STRING {
                bail!("extension value is not an OCTET STRING (tag 0x{value_tag:02X})");
            }
            found = Some(value_obj.value().to_vec());
        }
        Ok(found)
    }
}
