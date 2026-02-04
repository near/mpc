use serde::{Deserialize, Deserializer, Serialize, de};

#[derive(Serialize)]
pub(crate) struct JsonRpcRequest<P> {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: &'static str,
    pub(crate) method: &'static str,
    pub(crate) params: P,
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
