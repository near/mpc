use std::str::FromStr;

use assert_matches::assert_matches;
use attestation::collateral::{Collateral, CollateralError};
use attestation::{collateral_from_dcap, collateral_to_dcap};
use serde_json::json;
use test_utils::attestation::collateral;

#[test]
fn test_collateral_missing_field() {
    let mut json_value = collateral();
    // Remove a required field
    json_value.as_object_mut().unwrap().remove("tcb_info");

    let result = Collateral::try_from_json(json_value);

    assert_matches!(result, Err(CollateralError::MissingField(field)) => {
        assert_eq!(field, "tcb_info");
    });
}

#[test]
fn test_collateral_invalid_hex() {
    let mut json_value = collateral();
    // Set invalid hex value
    json_value["tcb_info_signature"] = json!("not_valid_hex");

    let result = Collateral::try_from_json(json_value);

    assert_matches!(result, Err(CollateralError::HexDecode { field, ..}) => {
        assert_eq!(field, "tcb_info_signature");
    });
}

#[test]
fn test_collateral_null_field() {
    let mut json_value = collateral();
    // Set field to null
    json_value["qe_identity"] = json!(null);

    let result = Collateral::try_from_json(json_value);

    assert_matches!(result, Err(CollateralError::MissingField(field)) => {
        assert_eq!(field, "qe_identity");
    });
}

#[test]
fn test_collateral_wrong_type_field() {
    let mut json_value = collateral();
    // Set field to wrong type (number instead of string)
    json_value["tcb_info_issuer_chain"] = json!(12345);

    let result = Collateral::try_from_json(json_value);

    assert_matches!(result, Err(CollateralError::MissingField(field)) => {
        assert_eq!(field, "tcb_info_issuer_chain");
    });
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
fn test_collateral_dcap_round_trip() {
    let json_value = collateral();
    let collateral = Collateral::try_from_json(json_value.clone()).unwrap();

    // mirror -> dcap_qvl type
    let quote_collateral_v3 = collateral_to_dcap(collateral);
    assert!(quote_collateral_v3.tcb_info.contains("\"id\":\"TDX\""));

    // dcap_qvl type -> mirror
    let new_collateral = collateral_from_dcap(quote_collateral_v3);
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

    assert_matches!(result, Err(CollateralError::InvalidJson));
}
