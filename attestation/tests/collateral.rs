use std::str::FromStr;

use attestation::collateral::{Collateral, CollateralError};
use dcap_qvl::QuoteCollateralV3;
use serde_json::json;
use test_utils::attestation::collateral;

#[test]
fn test_collateral_missing_field() {
    let mut json_value = collateral();
    // Remove a required field
    json_value.as_object_mut().unwrap().remove("tcb_info");

    let result = Collateral::try_from_json(json_value);

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
    let mut json_value = collateral();
    // Set invalid hex value
    json_value["tcb_info_signature"] = json!("not_valid_hex");

    let result = Collateral::try_from_json(json_value);

    assert!(result.is_err());
    match result.unwrap_err() {
        CollateralError::HexDecode { field, .. } => {
            assert_eq!(field, "tcb_info_signature");
        }
        _ => panic!("Expected HexDecode error"),
    }
}

#[test]
fn test_collateral_null_field() {
    let mut json_value = collateral();
    // Set field to null
    json_value["qe_identity"] = json!(null);

    let result = Collateral::try_from_json(json_value);

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
    let mut json_value = collateral();
    // Set field to wrong type (number instead of string)
    json_value["tcb_info_issuer_chain"] = json!(12345);

    let result = Collateral::try_from_json(json_value);

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
    let json_value = collateral();
    let collateral = Collateral::try_from_json(json_value).unwrap();

    // TCB info signature should be 64 hex chars (32 bytes)
    assert_eq!(collateral.tcb_info_signature.len(), 64);
    // QE identity signature should be 64 hex chars (32 bytes)
    assert_eq!(collateral.qe_identity_signature.len(), 64);
}

#[test]
fn test_derive_traits() {
    let json_value = collateral();
    let collateral = Collateral::try_from_json(json_value.clone()).unwrap();

    // Test From trait (should work through derive_more)
    let quote_collateral_v3: QuoteCollateralV3 = collateral.into();
    assert!(quote_collateral_v3.tcb_info.contains("\"id\":\"TDX\""));

    // Test creating from QuoteCollateralV3
    let new_collateral = Collateral::from(quote_collateral_v3);
    assert!(new_collateral.tcb_info.contains("\"id\":\"TDX\""));
}

#[test]
fn test_from_str_valid_json() {
    let json_str = serde_json::to_string(&collateral()).unwrap();
    let collateral = Collateral::from_str(&json_str).unwrap();

    assert!(collateral.tcb_info.contains("\"id\":\"TDX\""));
}

#[test]
fn test_from_str_invalid_json() {
    let invalid_json = "{ invalid json }";
    let result = Collateral::from_str(invalid_json);

    assert!(result.is_err());
    match result.unwrap_err() {
        CollateralError::InvalidJson => {}
        _ => panic!("Expected InvalidJson error"),
    }
}
