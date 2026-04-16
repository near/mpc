use reqwest::Client;
use serde::Deserialize;

/// Client for fetching attestation collateral from a local Intel PCCS.
pub struct PccsClient {
    pub pccs_base_url: reqwest::Url,
    pub http: Client,
}

/// Collateral fields returned to the caller, matching Phala's response format.
pub struct Collateral {
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub tcb_info_signature: String,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub qe_identity_signature: String,
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub pck_certificate_chain: String,
}

/// Parsed fields extracted from a TDX quote needed to query PCCS.
pub(crate) struct ParsedQuote {
    pub fmspc_hex: String,
    pub ca_type: &'static str,
    pub pck_cert_chain: String,
}

#[derive(Deserialize)]
struct TcbResponse {
    #[serde(alias = "tcbInfo")]
    tcb_info: serde_json::Value,
    signature: String,
}

#[derive(Deserialize)]
struct QeIdentityResponse {
    #[serde(alias = "enclaveIdentity")]
    enclave_identity: serde_json::Value,
    signature: String,
}

/// Parse a hex-encoded TDX quote and extract the fields needed for PCCS queries.
pub(crate) fn parse_quote(quote_hex: &str) -> anyhow::Result<ParsedQuote> {
    let quote_bytes = hex::decode(quote_hex)?;
    let quote = dcap_qvl::quote::Quote::parse(&quote_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse TDX quote: {e}"))?;

    let fmspc = quote
        .fmspc()
        .map_err(|e| anyhow::anyhow!("Failed to extract FMSPC: {e}"))?;
    let ca_type = quote
        .ca()
        .map_err(|e| anyhow::anyhow!("Failed to extract CA type: {e}"))?;
    let pck_cert_chain = quote
        .raw_cert_chain()
        .map_err(|e| anyhow::anyhow!("Failed to extract PCK cert chain: {e}"))?;
    let pck_cert_chain_str = String::from_utf8(pck_cert_chain.to_vec())
        .map_err(|e| anyhow::anyhow!("PCK cert chain is not valid UTF-8: {e}"))?;

    Ok(ParsedQuote {
        fmspc_hex: hex::encode(fmspc),
        ca_type,
        pck_cert_chain: pck_cert_chain_str,
    })
}

/// URL-decode a header value from a string. Extracted for testability.
pub(crate) fn url_decode(encoded: &str) -> anyhow::Result<String> {
    Ok(urlencoding::decode(encoded)?.into_owned())
}

impl PccsClient {
    /// Check if the upstream PCCS is reachable by hitting the TDX QE identity endpoint.
    pub async fn check_pccs_reachable(&self) -> bool {
        let url = format!("{}/tdx/certification/v4/qe/identity", self.base_url());
        matches!(self.http.get(&url).send().await, Ok(resp) if resp.status().is_success())
    }

    /// Parse a TDX quote and fetch all collateral from the local PCCS.
    pub async fn get_collateral(&self, quote_hex: &str) -> anyhow::Result<Collateral> {
        let parsed = parse_quote(quote_hex)?;

        tracing::info!(fmspc = %parsed.fmspc_hex, ca = %parsed.ca_type, "Parsed quote");

        // Fetch all collateral pieces from the local PCCS in parallel.
        // try_join! cancels remaining requests if any one fails.
        let (
            (tcb_info, tcb_info_signature, tcb_info_issuer_chain),
            (qe_identity, qe_identity_signature, qe_identity_issuer_chain),
            (pck_crl, pck_crl_issuer_chain),
            root_ca_crl,
        ) = tokio::try_join!(
            self.fetch_tcb_info(&parsed.fmspc_hex),
            self.fetch_qe_identity(),
            self.fetch_pck_crl(parsed.ca_type),
            self.fetch_root_ca_crl(),
        )?;

        Ok(Collateral {
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            pck_certificate_chain: parsed.pck_cert_chain,
        })
    }

    async fn fetch_tcb_info(&self, fmspc: &str) -> anyhow::Result<(String, String, String)> {
        let url = format!(
            "{}/tdx/certification/v4/tcb?fmspc={}",
            self.base_url(),
            fmspc
        );
        let resp = check_status(self.http.get(&url).send().await?, &url)?;
        let issuer_chain = get_decoded_header(&resp, "TCB-Info-Issuer-Chain")?;
        let body: TcbResponse = resp.json().await?;
        let tcb_info = serde_json::to_string(&body.tcb_info)?;
        Ok((tcb_info, body.signature, issuer_chain))
    }

    async fn fetch_qe_identity(&self) -> anyhow::Result<(String, String, String)> {
        let url = format!("{}/tdx/certification/v4/qe/identity", self.base_url());
        let resp = check_status(self.http.get(&url).send().await?, &url)?;
        let issuer_chain = get_decoded_header(&resp, "SGX-Enclave-Identity-Issuer-Chain")?;
        let body: QeIdentityResponse = resp.json().await?;
        let qe_identity = serde_json::to_string(&body.enclave_identity)?;
        Ok((qe_identity, body.signature, issuer_chain))
    }

    async fn fetch_pck_crl(&self, ca_type: &str) -> anyhow::Result<(String, String)> {
        let url = format!(
            "{}/sgx/certification/v4/pckcrl?ca={}",
            self.base_url(),
            ca_type
        );
        let resp = check_status(self.http.get(&url).send().await?, &url)?;
        let issuer_chain = get_decoded_header(&resp, "SGX-PCK-CRL-Issuer-Chain")?;
        // PCCS returns CRL as hex-encoded text
        let body = resp.text().await?;
        Ok((body, issuer_chain))
    }

    async fn fetch_root_ca_crl(&self) -> anyhow::Result<String> {
        let url = format!("{}/sgx/certification/v4/rootcacrl", self.base_url());
        let resp = check_status(self.http.get(&url).send().await?, &url)?;
        // PCCS returns CRL as hex-encoded text
        Ok(resp.text().await?)
    }

    fn base_url(&self) -> &str {
        self.pccs_base_url.as_str().trim_end_matches('/')
    }
}

/// Check that a PCCS response has a success status code.
fn check_status(resp: reqwest::Response, url: &str) -> anyhow::Result<reqwest::Response> {
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("PCCS returned {status} for {url}");
    }
    Ok(resp)
}

fn get_decoded_header(resp: &reqwest::Response, header_name: &str) -> anyhow::Result<String> {
    let raw = resp
        .headers()
        .get(header_name)
        .ok_or_else(|| anyhow::anyhow!("Missing header: {header_name}"))?
        .to_str()
        .map_err(|e| anyhow::anyhow!("Invalid header value for {header_name}: {e}"))?;
    url_decode(raw)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    fn test_quote_hex() -> String {
        let quote_json: Vec<u8> =
            serde_json::from_str(include_str!("../../test-utils/assets/quote.json")).unwrap();
        hex::encode(quote_json)
    }

    #[test]
    fn parse_quote__should_extract_fmspc_and_ca_type() {
        let parsed = parse_quote(&test_quote_hex()).unwrap();

        assert_eq!(parsed.fmspc_hex, "b0c06f000000");
        assert_eq!(parsed.ca_type, "platform");
    }

    #[test]
    fn parse_quote__should_extract_pck_cert_chain() {
        let parsed = parse_quote(&test_quote_hex()).unwrap();

        assert!(
            parsed
                .pck_cert_chain
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(parsed.pck_cert_chain.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn parse_quote__should_reject_invalid_hex() {
        let result = parse_quote("not_valid_hex!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_quote__should_reject_truncated_quote() {
        let result = parse_quote("0400020081000000");
        assert!(result.is_err());
    }

    #[test]
    fn url_decode__should_decode_percent_encoding() {
        let encoded = "-----BEGIN%20CERTIFICATE-----%0AMIICjT";
        let decoded = url_decode(encoded).unwrap();
        assert_eq!(decoded, "-----BEGIN CERTIFICATE-----\nMIICjT");
    }

    #[test]
    fn url_decode__should_pass_through_plain_text() {
        let plain = "no encoding here";
        assert_eq!(url_decode(plain).unwrap(), plain);
    }
}
