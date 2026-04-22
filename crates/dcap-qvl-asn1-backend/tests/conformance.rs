//! Conformance harness: prove [`Asn1DerConfig`] is a drop-in equivalent
//! of [`DefaultConfig`] on the vendored Intel sample corpus.
//!
//! Ported from `examples/asn1-der-backend/tests/conformance.rs` in
//! Phala-Network/dcap-qvl#145. Fixture source is documented at
//! `tests/fixtures/README.md`.
//!
//! The `malformed_extension_*` tests synthesise cert bytes with broken
//! extension shapes to pin the defensive checks in
//! `Asn1DerParsedCert::extension`; they are not part of the upstream
//! corpus.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use dcap_qvl::{
    config::{Config, EcdsaSigEncoder, ParsedCert, X509Codec},
    configs::DefaultConfig,
    quote::Quote,
    QuoteCollateralV3,
};
use dcap_qvl_asn1_backend::{Asn1DerCertBackend, Asn1DerConfig, Asn1DerSigEncoder};

const SGX_QUOTE: &[u8] = include_bytes!("fixtures/sgx_quote");
const TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote");
const TDX_COLLATERAL: &[u8] = include_bytes!("fixtures/tdx_quote_collateral.json");

/// DER-encoded body of the Intel SGX OID (1.2.840.113741.1.13.1) — same
/// constant used by the in-tree `dcap-qvl` test harness.
const SGX_EXTENSION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01];

fn pck_leaf_certs() -> Vec<Vec<u8>> {
    [SGX_QUOTE, TDX_QUOTE]
        .into_iter()
        .map(|raw| {
            let q = Quote::parse(raw).expect("parse quote");
            let pem = q.raw_cert_chain().expect("cert chain");
            pem::parse_many(pem)
                .expect("parse pem")
                .into_iter()
                .next()
                .expect("leaf cert")
                .into_contents()
        })
        .collect()
}

#[test]
fn parsed_cert_matches_default_on_sample_corpus() {
    for cert_der in pck_leaf_certs() {
        let custom = Asn1DerCertBackend::from_der(&cert_der).expect("custom from_der");
        let default =
            <DefaultConfig as Config>::X509::from_der(&cert_der).expect("default from_der");

        // DefaultConfig's issuer_dn returns RFC 4514 form; the asn1_der
        // backend returns a comma-joined sequence of printable RDN values.
        // They are not byte-identical, but they MUST agree on the substrings
        // `intel::pck_ca_with` uses to classify the issuing CA.
        let custom_issuer = custom.issuer_dn().expect("custom issuer_dn");
        let default_issuer = default.issuer_dn().expect("default issuer_dn");
        for needle in ["Processor", "Platform"] {
            assert_eq!(
                custom_issuer.contains(needle),
                default_issuer.contains(needle),
                "issuer DN substring match diverged for {needle:?}: \
                 custom={custom_issuer:?} default={default_issuer:?}",
            );
        }

        // The SGX extension OCTET STRING contents MUST be byte-identical —
        // any divergence would break TCB matching downstream.
        assert_eq!(
            custom.extension(SGX_EXTENSION_OID).expect("custom ext"),
            default.extension(SGX_EXTENSION_OID).expect("default ext"),
            "Intel SGX extension bytes diverged",
        );

        // Missing extensions: both must agree on `None`.
        let bogus_oid: &[u8] = &[0x2A, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(
            custom.extension(bogus_oid).expect("custom missing"),
            default.extension(bogus_oid).expect("default missing"),
            "missing-extension behavior diverged",
        );
    }
}

/// Edge cases for DER INTEGER encoding: high bit set (must prepend `0x00`),
/// leading zeros (must be stripped), all-zero (must encode as `02 01 00`),
/// and mixed values.
fn encode_test_vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    fn trailing(b: u8) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[31] = b;
        v
    }
    vec![
        (vec![0x80; 32], vec![0xFF; 32]),
        (trailing(0x42), vec![0x7F; 32]),
        (vec![0x55; 32], trailing(0x01)),
        (vec![0u8; 32], vec![0u8; 32]),
        ((0u8..32).collect(), (32u8..64).collect()),
    ]
}

#[test]
fn encode_ecdsa_sig_matches_default() {
    for (r, s) in encode_test_vectors() {
        let custom = Asn1DerSigEncoder::encode_ecdsa_sig(&r, &s).expect("custom encode");
        let default = <DefaultConfig as Config>::SigEncoder::encode_ecdsa_sig(&r, &s)
            .expect("default encode");
        assert_eq!(
            custom, default,
            "encode_ecdsa_sig diverged for r={:02x?} s={:02x?}",
            &r, &s,
        );
    }
}

/// DER tags used by the malformed-cert synthesis tests below.
mod der_tags {
    pub const SEQUENCE: u8 = 0x30;
    pub const OID: u8 = 0x06;
    pub const OCTET_STRING: u8 = 0x04;
    pub const BOOLEAN: u8 = 0x01;
    /// `[3] EXPLICIT` wrapper used for `TBSCertificate.extensions`.
    pub const CTX_3: u8 = 0xA3;
}

/// Minimal DER TLV writer: emits `tag || length || value`.
///
/// Lengths are encoded in DER definite form (short for < 128, long-form
/// otherwise). Enough for the test fixtures below; not a general encoder.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let first_nonzero = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let nbytes = be.len() - first_nonzero;
        out.push(0x80 | nbytes as u8);
        out.extend_from_slice(&be[first_nonzero..]);
    }
    out.extend_from_slice(value);
    out
}

/// Parse `(tag, header_len, value_len)` from a DER TLV starting at `buf[0]`.
fn parse_tlv_header(buf: &[u8]) -> (u8, usize, usize) {
    let tag = buf[0];
    let first_len = buf[1];
    if first_len < 0x80 {
        (tag, 2, first_len as usize)
    } else {
        let nbytes = (first_len & 0x7F) as usize;
        let len = buf[2..2 + nbytes]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (tag, 2 + nbytes, len)
    }
}

/// Splice a new `extensions[3]` body into a real PCK leaf cert, keeping
/// everything else intact. Returns a fresh DER-encoded Certificate whose
/// custom parser will reach into the rewritten extensions.
///
/// The base cert is assumed to be a v3 cert with `extensions[3]` as the
/// last element of `tbsCertificate` (true for every Intel PCK cert).
fn splice_extensions(cert_der: &[u8], new_extensions_seq_body: &[u8]) -> Vec<u8> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (outer_tag, outer_hdr, outer_len) = parse_tlv_header(cert_der);
    assert_eq!(outer_tag, der_tags::SEQUENCE, "outer must be SEQUENCE");
    let outer_body = &cert_der[outer_hdr..outer_hdr + outer_len];

    // tbsCertificate is the first element.
    let (tbs_tag, tbs_hdr, tbs_len) = parse_tlv_header(outer_body);
    assert_eq!(tbs_tag, der_tags::SEQUENCE, "tbs must be SEQUENCE");
    let tbs_body = &outer_body[tbs_hdr..tbs_hdr + tbs_len];
    let after_tbs = &outer_body[tbs_hdr + tbs_len..]; // signatureAlgorithm + signatureValue

    // Walk tbs children to find the `[3] EXPLICIT` extensions wrapper.
    let mut pos = 0usize;
    let mut ext_wrapper_start: Option<usize> = None;
    while pos < tbs_body.len() {
        let (tag, hdr, vlen) = parse_tlv_header(&tbs_body[pos..]);
        if tag == der_tags::CTX_3 {
            ext_wrapper_start = Some(pos);
            break;
        }
        pos += hdr + vlen;
    }
    let ext_wrapper_start =
        ext_wrapper_start.expect("PCK cert must carry an extensions[3] wrapper");

    // Rebuild tbs: keep everything up to (not including) the old [3]
    // wrapper, then append a fresh [3] EXPLICIT wrapping the new
    // extensions SEQUENCE (SEQUENCE OF Extension).
    let mut new_tbs_body = tbs_body[..ext_wrapper_start].to_vec();
    let new_ext_seq = tlv(der_tags::SEQUENCE, new_extensions_seq_body);
    let new_ext_wrapper = tlv(der_tags::CTX_3, &new_ext_seq);
    new_tbs_body.extend_from_slice(&new_ext_wrapper);
    let new_tbs = tlv(der_tags::SEQUENCE, &new_tbs_body);

    // Rebuild outer Certificate with the new tbs + original signatureAlgorithm + signatureValue.
    let mut new_outer_body = new_tbs;
    new_outer_body.extend_from_slice(after_tbs);
    tlv(der_tags::SEQUENCE, &new_outer_body)
}

/// Synthetic OID body used for crafted extension tests. Arbitrary; we
/// only care that it's a stable reference shared between the cert we
/// craft and the lookup we perform.
const TEST_OID: &[u8] = &[0x2A, 0x03, 0x04];

/// Helper: build a legitimate `Extension SEQUENCE OF Extension` containing
/// one extension with our `TEST_OID` and `{oid, critical, value}` shape.
/// Serves as a sanity check that the splicing helper produces parseable
/// DER (both backends should succeed).
#[test]
fn splice_extensions_sanity_check() {
    for cert_der in pck_leaf_certs() {
        let oid_tlv = tlv(der_tags::OID, TEST_OID);
        let critical_tlv = tlv(der_tags::BOOLEAN, &[0xFF]);
        let value_tlv = tlv(der_tags::OCTET_STRING, b"hello");
        let ext = tlv(
            der_tags::SEQUENCE,
            &[oid_tlv, critical_tlv, value_tlv].concat(),
        );
        let spliced = splice_extensions(&cert_der, &ext);

        let custom = Asn1DerCertBackend::from_der(&spliced).expect("custom parses spliced cert");
        let custom_value = custom.extension(TEST_OID).expect("custom reads extension");
        assert_eq!(custom_value.as_deref(), Some(b"hello".as_slice()));

        // DefaultConfig must also parse this — if the splice were producing
        // malformed DER, we would catch it here.
        let default = <DefaultConfig as Config>::X509::from_der(&spliced)
            .expect("default parses spliced cert");
        let default_value = default
            .extension(TEST_OID)
            .expect("default reads extension");
        assert_eq!(default_value, custom_value);
    }
}

/// M1 — `Extension` with only `{oid, critical}` and no `extnValue`.
///
/// The shape gate `(2..=3).contains(&ext_len)` passes (len = 2) but the
/// tail element is a BOOLEAN, not an OCTET STRING. The custom backend
/// must reject via the tag check on the value. The audited default
/// rejects at `from_der` (typed `extnValue: OctetString` decode fails),
/// so we only assert on the custom result — the point is that the
/// custom parser does not silently hand back the BOOLEAN bytes as the
/// extension value.
#[test]
fn malformed_extension_missing_value_is_rejected() {
    for cert_der in pck_leaf_certs() {
        let oid_tlv = tlv(der_tags::OID, TEST_OID);
        let critical_tlv = tlv(der_tags::BOOLEAN, &[0xFF]);
        let ext = tlv(der_tags::SEQUENCE, &[oid_tlv, critical_tlv].concat());
        let spliced = splice_extensions(&cert_der, &ext);

        let custom = Asn1DerCertBackend::from_der(&spliced).expect("from_der");
        let err = custom
            .extension(TEST_OID)
            .expect_err("missing extnValue must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("OCTET STRING"),
            "expected OCTET-STRING-tag error, got: {msg}"
        );
    }
}

/// M2 — `Extension` whose `extnID` is shaped like an OID byte-wise but
/// carries a different tag (here OCTET STRING). The custom backend must
/// reject via the tag check on `extn_id` so an attacker can never
/// byte-match a known OID through a non-OID container.
#[test]
fn malformed_extension_non_oid_extnid_is_rejected() {
    for cert_der in pck_leaf_certs() {
        let bogus_extnid_tlv = tlv(der_tags::OCTET_STRING, TEST_OID);
        let value_tlv = tlv(der_tags::OCTET_STRING, b"attacker-payload");
        let ext = tlv(der_tags::SEQUENCE, &[bogus_extnid_tlv, value_tlv].concat());
        let spliced = splice_extensions(&cert_der, &ext);

        let custom = Asn1DerCertBackend::from_der(&spliced).expect("from_der");
        let err = custom
            .extension(TEST_OID)
            .expect_err("non-OID extnID must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("OBJECT IDENTIFIER"),
            "expected OID-tag error, got: {msg}"
        );
    }
}

/// M3 — `Extension` whose trailing element carries a non-OCTET-STRING
/// tag (here BIT STRING). The custom backend must reject via the value
/// tag check.
#[test]
fn malformed_extension_non_octet_string_value_is_rejected() {
    for cert_der in pck_leaf_certs() {
        let oid_tlv = tlv(der_tags::OID, TEST_OID);
        // 0x03 == BIT STRING; leading 0x00 is the unused-bits count per X.690.
        let bogus_value_tlv = tlv(0x03, &[0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
        let ext = tlv(der_tags::SEQUENCE, &[oid_tlv, bogus_value_tlv].concat());
        let spliced = splice_extensions(&cert_der, &ext);

        let custom = Asn1DerCertBackend::from_der(&spliced).expect("from_der");
        let err = custom
            .extension(TEST_OID)
            .expect_err("non-OCTET-STRING extnValue must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("OCTET STRING"),
            "expected OCTET-STRING-tag error, got: {msg}"
        );
    }
}

/// M4 — trailing bytes appended after the outer Certificate SEQUENCE.
///
/// Documents a known divergence: the audited `der` crate rejects
/// (enforces full-input consumption) while `asn1_der::DerObject::decode`
/// does not, so the custom backend accepts. This is safe under the
/// Intel-signed-chain constraint (webpki re-validates the signed TBS
/// region), but it is worth a test so the asymmetry is explicit and any
/// future tightening is caught by a test failure rather than silently
/// changing behaviour.
#[test]
fn trailing_bytes_after_cert_diverge_documented() {
    for cert_der in pck_leaf_certs() {
        let mut with_trailing = cert_der;
        with_trailing.extend_from_slice(b"\x00\x00trailing-garbage");

        // Custom accepts.
        Asn1DerCertBackend::from_der(&with_trailing)
            .expect("custom accepts trailing bytes (documented divergence)");

        // Default rejects.
        assert!(
            <DefaultConfig as Config>::X509::from_der(&with_trailing).is_err(),
            "default must reject trailing bytes; if this starts succeeding, \
             the documented divergence has closed and this test should be updated"
        );
    }
}

#[test]
fn verify_with_asn1_der_config_matches_default() {
    let collateral: QuoteCollateralV3 = serde_json::from_slice(TDX_COLLATERAL).expect("collateral");
    // The vendored TDX collateral has long since expired. Pin `now` to
    // just before its `nextUpdate` so the test is deterministic.
    let tcb_json: serde_json::Value = serde_json::from_str(&collateral.tcb_info).expect("tcb json");
    let next_update_str = tcb_json
        .get("nextUpdate")
        .and_then(|v| v.as_str())
        .expect("nextUpdate str");
    let next_update =
        chrono::DateTime::parse_from_rfc3339(next_update_str).expect("nextUpdate parse");
    let now = next_update.timestamp() as u64 - 1;

    let default_result = dcap_qvl::verify::verify(TDX_QUOTE, &collateral, now);
    let custom_result = dcap_qvl::verify::verify_with::<Asn1DerConfig>(TDX_QUOTE, &collateral, now);

    assert_eq!(
        default_result.map_err(|e| e.to_string()),
        custom_result.map_err(|e| e.to_string()),
        "verify_with::<Asn1DerConfig> diverged from verify (DefaultConfig)",
    );
}
