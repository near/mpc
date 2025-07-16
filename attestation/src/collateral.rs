use alloc::{string::String, vec::Vec};
use dcap_qvl::QuoteCollateralV3;
use derive_more::{Deref, From, Into};
use hex::FromHexError;
use serde_json::Value;

/// Supplemental data for the TEE quote, including Intel certificates to verify it came from
/// genuine Intel hardware, along with details about the Trusted Computing Base (TCB)
/// versioning, status, and other relevant info.
#[derive(From, Deref, Into, Debug)]
pub struct Collateral(QuoteCollateralV3);

impl TryFrom<Value> for Collateral {
    type Error = CollateralError;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        fn get_str(v: &Value, key: &str) -> Result<String, CollateralError> {
            v.get(key)
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or_else(|| CollateralError::MissingField(String::from(key)))
        }

        fn get_hex(v: &Value, key: &str) -> Result<Vec<u8>, CollateralError> {
            let hex_str = get_str(v, key)?;
            hex::decode(hex_str).map_err(|e| CollateralError::HexDecode(String::from(key), e))
        }

        let quote_collateral = QuoteCollateralV3 {
            tcb_info_issuer_chain: get_str(&v, "tcb_info_issuer_chain")?,
            tcb_info: get_str(&v, "tcb_info")?,
            tcb_info_signature: get_hex(&v, "tcb_info_signature")?,
            qe_identity_issuer_chain: get_str(&v, "qe_identity_issuer_chain")?,
            qe_identity: get_str(&v, "qe_identity")?,
            qe_identity_signature: get_hex(&v, "qe_identity_signature")?,
        };

        Ok(Self(quote_collateral))
    }
}

#[derive(Debug)]
pub enum CollateralError {
    MissingField(String),
    HexDecode(String, FromHexError),
}

impl core::fmt::Display for CollateralError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CollateralError::MissingField(field) => {
                write!(f, "Missing or invalid field: {}", field)
            }
            CollateralError::HexDecode(field, e) => {
                write!(f, "Failed to decode hex field '{}': {}", field, e)
            }
        }
    }
}

impl From<CollateralError> for anyhow::Error {
    fn from(err: CollateralError) -> Self {
        anyhow::anyhow!("{}", err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_collateral_json() -> Value {
        json!({
            "tcb_info_issuer_chain": "-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n",
            "tcb_info": "{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-03-11T00:36:15Z\",\"nextUpdate\":\"2025-04-10T00:36:15Z\",\"fmspc\":\"20a06f000000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tdxModule\":{\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tdxModuleIdentities\":[{\"id\":\"TDX_03\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":3},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]},{\"id\":\"TDX_01\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}],\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}",
            "tcb_info_signature": "dff1380a12d533bff4ad7f69fd0355ad97ff034b42c8269e26e40e3d585dffff3e55bf21f8cda481d3c163fafcd4eab11c8818ba6aa7553ba6866bce06b56a95",
            "qe_identity_issuer_chain": "-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n",
            "qe_identity": "{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-03-10T23:38:16Z\",\"nextUpdate\":\"2025-04-09T23:38:16Z\",\"tcbEvaluationDataNumber\":17,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]}",
            "qe_identity_signature": "920d5f18df6da142a667caf71844d45dfd4de3e3b14f846bae92a3e52a9c765d855b9a8b4b54307dd3feae30f28f09888a3200c29584d7c50d42f85275afe6cc"
        })
    }

    #[test]
    fn test_collateral_missing_field() {
        let mut json_value = create_test_collateral_json();
        // Remove a required field
        json_value.as_object_mut().unwrap().remove("tcb_info");

        let result = Collateral::try_from(json_value);

        assert!(result.is_err());
        match result.unwrap_err() {
            CollateralError::MissingField(field) => {
                assert_eq!(field, "tcb_info");
            }
            _ => panic!("Expected MissingField error"),
        }
    }

    #[test]
    fn test_collateral_invalid_hex() {
        let mut json_value = create_test_collateral_json();
        // Set invalid hex value
        json_value["tcb_info_signature"] = json!("not_valid_hex");

        let result = Collateral::try_from(json_value);

        assert!(result.is_err());
        match result.unwrap_err() {
            CollateralError::HexDecode(field, _) => {
                assert_eq!(field, "tcb_info_signature");
            }
            _ => panic!("Expected HexDecode error"),
        }
    }

    #[test]
    fn test_collateral_null_field() {
        let mut json_value = create_test_collateral_json();
        // Set field to null
        json_value["qe_identity"] = json!(null);

        let result = Collateral::try_from(json_value);

        assert!(result.is_err());
        match result.unwrap_err() {
            CollateralError::MissingField(field) => {
                assert_eq!(field, "qe_identity");
            }
            _ => panic!("Expected MissingField error"),
        }
    }

    #[test]
    fn test_collateral_wrong_type_field() {
        let mut json_value = create_test_collateral_json();
        // Set field to wrong type (number instead of string)
        json_value["tcb_info_issuer_chain"] = json!(12345);

        let result = Collateral::try_from(json_value);

        assert!(result.is_err());
        match result.unwrap_err() {
            CollateralError::MissingField(field) => {
                assert_eq!(field, "tcb_info_issuer_chain");
            }
            _ => panic!("Expected MissingField error"),
        }
    }

    #[test]
    fn test_hex_signature_lengths() {
        let json_value = create_test_collateral_json();
        let collateral = Collateral::try_from(json_value).unwrap();

        // TCB info signature should be 64 hex chars (32 bytes)
        assert_eq!(collateral.tcb_info_signature.len(), 64);
        // QE identity signature should be 64 hex chars (32 bytes)
        assert_eq!(collateral.qe_identity_signature.len(), 64);
    }

    #[test]
    fn test_derive_traits() {
        let json_value = create_test_collateral_json();
        let collateral = Collateral::try_from(json_value.clone()).unwrap();

        // Test From trait (should work through derive_more)
        let quote_collateral_v3: QuoteCollateralV3 = collateral.into();
        assert!(quote_collateral_v3.tcb_info.contains("\"id\":\"TDX\""));

        // Test creating from QuoteCollateralV3
        let new_collateral = Collateral::from(quote_collateral_v3);
        assert!(new_collateral.tcb_info.contains("\"id\":\"TDX\""));
    }
}
