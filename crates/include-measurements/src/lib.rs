use anyhow::Context;
use attestation::tcb_info::TcbInfo;
use proc_macro::TokenStream;
use quote::quote;
use std::env;
use std::fs;
use std::path::Path;
use syn::{LitStr, parse_macro_input};

/// Expands TCB info measurements from the given JSON file
/// into an `ExpectedMeasurements` struct literal.
///
/// # Usage
///
/// ```rust,ignore
/// use include_measurements::include_measurements;
/// use attestation::measurements::ExpectedMeasurements;
///
/// let measurements: ExpectedMeasurements = include_measurements!("path/to/tcb_info.json");
/// ```
#[proc_macro]
pub fn include_measurements(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let file_path = input.value();

    try_include_measurements(&file_path).unwrap_or_compile_error(input.span())
}

fn try_include_measurements(file_path: &str) -> anyhow::Result<proc_macro2::TokenStream> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR environment variable not set")?;
    let full_path = Path::new(&manifest_dir).join(file_path);

    let json_content = fs::read_to_string(&full_path)
        .with_context(|| format!("Failed to read file '{}'", full_path.display()))?;

    generate_measurements_tokens(&json_content).with_context(|| {
        format!(
            "Failed to generate measurements from file '{}'",
            full_path.display()
        )
    })
}

fn generate_measurements_tokens(json_content: &str) -> anyhow::Result<proc_macro2::TokenStream> {
    let TcbInfo {
        rtmr0,
        rtmr1,
        rtmr2,
        mrtd,
        event_log,
        ..
    } = serde_json::from_str(json_content).context("Failed to parse TCB info JSON")?;

    let key_provider_event_digests: Vec<_> = event_log
        .iter()
        .filter(|event| event.event == "key-provider")
        .map(|event| event.digest.as_slice())
        .collect();

    anyhow::ensure!(
        key_provider_event_digests.len() == 1,
        "Expected exactly one key-provider event, found {}",
        key_provider_event_digests.len()
    );

    let key_provider_event_digest = key_provider_event_digests[0];

    let expanded = quote! {
        ExpectedMeasurements {
            rtmrs: Measurements {
                mrtd: [#(#mrtd),*],
                rtmr0: [#(#rtmr0),*],
                rtmr1: [#(#rtmr1),*],
                rtmr2: [#(#rtmr2),*],
            },
            key_provider_event_digest: [#(#key_provider_event_digest),*],
        }
    };

    Ok(expanded)
}

trait ToCompileError {
    type Output;
    fn unwrap_or_compile_error(self, span: proc_macro2::Span) -> Self::Output;
}

impl ToCompileError for anyhow::Result<proc_macro2::TokenStream> {
    type Output = TokenStream;

    fn unwrap_or_compile_error(self, span: proc_macro2::Span) -> Self::Output {
        match self {
            Ok(tokens) => TokenStream::from(tokens),
            Err(e) => syn::Error::new(span, format!("{:#}", e))
                .to_compile_error()
                .into(),
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    const TEST_TCB_INFO_JSON: &str = r#"{
        "mrtd": "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
        "rtmr0": "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
        "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
        "rtmr2": "dbf4924c07f5066f3dc6859844184344306aa3263817153dcaee85af97d23e0c0b96efe0731d8865a8747e51b9e351ac",
        "rtmr3": "e0d4a068296ebdfc4c9cbf4777663c65c0da4405b8380f28e344f1fab52490264944ff8ccfde112b85eb1d997785e2ac",
        "os_image_hash": "",
        "compose_hash": "3efecc42bdef4cb42fa354e9b84fe00e9d82b5397a739e0b03188ab80d72ed81",
        "device_id": "7a82191bd4dedb9d716e3aa422963cf1009f36e3068404a0322feca1ce517dc9",
        "app_compose": "test_compose",
        "event_log": [
            {
                "imr": 3,
                "event_type": 134217729,
                "digest": "74ca939b8c3c74aab3c30966a788f7743951d54a936a711dd01422f003ff9df6666f3cc54975d2e4f35c829865583f0f",
                "event": "key-provider",
                "event_payload": "7b226e616d65223a226c6f63616c2d736778222c226964223a2231623761343933373834303332343962363938366139303738343463616230393231656361333264643437653635376633633130333131636361656363663862227d"
            }
        ]
    }"#;

    #[test]
    fn generate_measurements_tokens__should_generate_expected_measurements_struct_literal() {
        // Given
        let json_content = TEST_TCB_INFO_JSON;

        // When
        let result_str = generate_measurements_tokens(json_content)
            .unwrap()
            .to_string();

        // Then
        assert_eq!(
            result_str,
            "ExpectedMeasurements { rtmrs : Measurements { mrtd : [240u8 , 109u8 , 253u8 , 166u8 , 220u8 , 225u8 , 207u8 , 144u8 , 77u8 , 78u8 , 43u8 , 171u8 , 29u8 , 195u8 , 112u8 , 99u8 , 76u8 , 249u8 , 92u8 , 239u8 , 162u8 , 206u8 , 178u8 , 222u8 , 46u8 , 238u8 , 18u8 , 124u8 , 147u8 , 130u8 , 105u8 , 128u8 , 144u8 , 215u8 , 164u8 , 161u8 , 62u8 , 20u8 , 197u8 , 54u8 , 236u8 , 108u8 , 156u8 , 60u8 , 143u8 , 168u8 , 112u8 , 119u8] , rtmr0 : [230u8 , 115u8 , 190u8 , 47u8 , 112u8 , 190u8 , 239u8 , 183u8 , 11u8 , 72u8 , 166u8 , 16u8 , 158u8 , 237u8 , 71u8 , 21u8 , 215u8 , 39u8 , 13u8 , 70u8 , 131u8 , 179u8 , 191u8 , 53u8 , 111u8 , 162u8 , 95u8 , 175u8 , 191u8 , 26u8 , 167u8 , 110u8 , 57u8 , 233u8 , 18u8 , 126u8 , 110u8 , 104u8 , 140u8 , 205u8 , 169u8 , 139u8 , 218u8 , 177u8 , 212u8 , 212u8 , 127u8 , 70u8] , rtmr1 : [167u8 , 181u8 , 35u8 , 39u8 , 141u8 , 79u8 , 145u8 , 78u8 , 232u8 , 223u8 , 14u8 , 200u8 , 12u8 , 209u8 , 195u8 , 212u8 , 152u8 , 203u8 , 241u8 , 21u8 , 43u8 , 12u8 , 94u8 , 175u8 , 101u8 , 186u8 , 217u8 , 66u8 , 80u8 , 114u8 , 135u8 , 74u8 , 63u8 , 207u8 , 137u8 , 30u8 , 139u8 , 1u8 , 113u8 , 61u8 , 61u8 , 153u8 , 55u8 , 227u8 , 224u8 , 210u8 , 108u8 , 21u8] , rtmr2 : [219u8 , 244u8 , 146u8 , 76u8 , 7u8 , 245u8 , 6u8 , 111u8 , 61u8 , 198u8 , 133u8 , 152u8 , 68u8 , 24u8 , 67u8 , 68u8 , 48u8 , 106u8 , 163u8 , 38u8 , 56u8 , 23u8 , 21u8 , 61u8 , 202u8 , 238u8 , 133u8 , 175u8 , 151u8 , 210u8 , 62u8 , 12u8 , 11u8 , 150u8 , 239u8 , 224u8 , 115u8 , 29u8 , 136u8 , 101u8 , 168u8 , 116u8 , 126u8 , 81u8 , 185u8 , 227u8 , 81u8 , 172u8] , } , key_provider_event_digest : [116u8 , 202u8 , 147u8 , 155u8 , 140u8 , 60u8 , 116u8 , 170u8 , 179u8 , 195u8 , 9u8 , 102u8 , 167u8 , 136u8 , 247u8 , 116u8 , 57u8 , 81u8 , 213u8 , 74u8 , 147u8 , 106u8 , 113u8 , 29u8 , 208u8 , 20u8 , 34u8 , 240u8 , 3u8 , 255u8 , 157u8 , 246u8 , 102u8 , 111u8 , 60u8 , 197u8 , 73u8 , 117u8 , 210u8 , 228u8 , 243u8 , 92u8 , 130u8 , 152u8 , 101u8 , 88u8 , 63u8 , 15u8] , }"
        );
    }

    #[test]
    fn generate_measurements_tokens__should_fail_with_invalid_json() {
        // Given
        let invalid_json = "invalid json";

        // When
        let result = generate_measurements_tokens(invalid_json);

        // Then
        let err = result.expect_err("Invalid JSON should fail to parse");
        assert!(err.to_string().contains("Failed to parse TCB info JSON"));
    }

    #[test]
    fn generate_measurements_tokens__should_fail_with_missing_key_provider_event() {
        // Given
        let json_without_key_provider = r#"{
            "mrtd": "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
            "rtmr0": "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
            "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
            "rtmr2": "dbf4924c07f5066f3dc6859844184344306aa3263817153dcaee85af97d23e0c0b96efe0731d8865a8747e51b9e351ac",
            "rtmr3": "e0d4a068296ebdfc4c9cbf4777663c65c0da4405b8380f28e344f1fab52490264944ff8ccfde112b85eb1d997785e2ac",
            "os_image_hash": "",
            "compose_hash": "3efecc42bdef4cb42fa354e9b84fe00e9d82b5397a739e0b03188ab80d72ed81",
            "device_id": "7a82191bd4dedb9d716e3aa422963cf1009f36e3068404a0322feca1ce517dc9",
            "app_compose": "test_compose",
            "event_log": []
        }"#;

        // When
        let result = generate_measurements_tokens(json_without_key_provider);

        // Then
        let err = result.expect_err("Missing key-provider event should fail");
        assert!(err
            .to_string()
            .contains("Expected exactly one key-provider event, found 0"));
    }

    #[test]
    fn generate_measurements_tokens__should_fail_with_multiple_key_provider_events() {
        // Given
        let json_with_multiple_key_providers = r#"{
            "mrtd": "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
            "rtmr0": "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
            "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
            "rtmr2": "dbf4924c07f5066f3dc6859844184344306aa3263817153dcaee85af97d23e0c0b96efe0731d8865a8747e51b9e351ac",
            "rtmr3": "e0d4a068296ebdfc4c9cbf4777663c65c0da4405b8380f28e344f1fab52490264944ff8ccfde112b85eb1d997785e2ac",
            "os_image_hash": "",
            "compose_hash": "3efecc42bdef4cb42fa354e9b84fe00e9d82b5397a739e0b03188ab80d72ed81",
            "device_id": "7a82191bd4dedb9d716e3aa422963cf1009f36e3068404a0322feca1ce517dc9",
            "app_compose": "test_compose",
            "event_log": [
                {
                    "imr": 3,
                    "event_type": 134217729,
                    "digest": "74ca939b8c3c74aab3c30966a788f7743951d54a936a711dd01422f003ff9df6666f3cc54975d2e4f35c829865583f0f",
                    "event": "key-provider",
                    "event_payload": "payload1"
                },
                {
                    "imr": 3,
                    "event_type": 134217729,
                    "digest": "84ca939b8c3c74aab3c30966a788f7743951d54a936a711dd01422f003ff9df6666f3cc54975d2e4f35c829865583f0f",
                    "event": "key-provider",
                    "event_payload": "payload2"
                }
            ]
        }"#;

        // When
        let result = generate_measurements_tokens(json_with_multiple_key_providers);

        // Then
        let err = result.expect_err("Multiple key-provider events should fail");
        assert!(err
            .to_string()
            .contains("Expected exactly one key-provider event, found 2"));
    }
}
