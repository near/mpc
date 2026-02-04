use serde::{Deserialize, Deserializer, Serialize, de};

#[derive(Serialize)]
pub(crate) struct JsonRpcRequest<P> {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: &'static str,
    pub(crate) method: &'static str,
    pub(crate) rpc_parameters: P,
}

#[derive(Debug, Deserialize, PartialEq)]
pub(crate) struct JsonRpcError {
    pub(crate) code: i32,
    pub(crate) message: String,
}

#[derive(Debug, PartialEq)]
pub(crate) struct JsonRpcResponse<T>(pub(crate) Result<T, JsonRpcError>);

impl<'de, T> Deserialize<'de> for JsonRpcResponse<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Shadow struct mirroring the raw JSON wire format
        #[derive(Deserialize)]
        struct RawRpcResponse<T> {
            result: Option<T>,
            error: Option<JsonRpcError>,
        }

        let raw = RawRpcResponse::<T>::deserialize(deserializer)?;

        if let Some(err) = raw.error {
            return Ok(JsonRpcResponse(Err(err)));
        }

        if let Some(res) = raw.result {
            return Ok(JsonRpcResponse(Ok(res)));
        }

        Err(de::Error::custom(
            "Response must contain either 'result' or 'error'",
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;

    #[test]
    fn should_deserialize_successful_response() {
        // Given
        let json = r#"{
            "result": "Everything is fine",
            "error": null,
            "id": 1
        }"#;

        // When
        let response: JsonRpcResponse<String> = from_str(json).expect("Should deserialize");

        // Then
        assert_eq!(
            response,
            JsonRpcResponse(Ok("Everything is fine".to_string()))
        );
    }

    #[test]
    fn should_deserialize_error_response() {
        // given
        let json: &str = r#"{
            "result": null,
            "error": {
                "code": 500,
                "message": "Something went wrong"
            },
            "id": 1
        }"#;

        // When
        let response: JsonRpcResponse<String> = from_str(json).expect("Should deserialize");

        // Then
        assert_eq!(
            response,
            JsonRpcResponse(Err(JsonRpcError {
                code: 500,
                message: "Something went wrong".to_string(),
            }))
        );
    }

    #[test]
    // Some RPC 1.0 implementations might omit the null field entirely.
    fn should_handle_missing_null_fields_gracefully() {
        // Given
        let json = r#"{
            "result": "Still works",
            "id": 1
        }"#;

        // When
        let response: JsonRpcResponse<String> = from_str(json).expect("Should deserialize");

        // Then
        assert_eq!(response, JsonRpcResponse(Ok("Still works".to_string())));
    }

    #[test]
    fn should_fail_when_neither_result_nor_error_is_present() {
        // Given
        let json = r#"{
            "id": 1
        }"#;

        // When
        let result: Result<JsonRpcResponse<String>, _> = from_str(json);

        // Then
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Response must contain either 'result' or 'error'"
        );
    }

    #[test]
    fn should_deserialize_complex_struct_result() {
        // Given
        #[derive(Deserialize, PartialEq, Debug)]
        struct MyData {
            id: u32,
            active: bool,
        }

        let json = r#"{
            "result": { "id": 99, "active": true },
            "error": null,
            "id": 1
        }"#;

        // When
        let response: JsonRpcResponse<MyData> = from_str(json).expect("Should deserialize");

        // Then
        assert_eq!(
            response,
            JsonRpcResponse(Ok(MyData {
                id: 99,
                active: true
            }))
        );
    }
}
