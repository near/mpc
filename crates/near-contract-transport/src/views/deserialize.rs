use serde::de::DeserializeOwned;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct DeserializationError(String);

impl DeserializationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub type Deserializer<T> = fn(&[u8]) -> Result<T, DeserializationError>;

/// Selects the [`Deserializer`] a view call decodes `T` with; see [`Json`] and [`Borsh`].
pub trait DeserializeAs<T> {
    fn deserializer() -> Deserializer<T>;
}

pub struct Json;

impl<T: DeserializeOwned> DeserializeAs<T> for Json {
    fn deserializer() -> Deserializer<T> {
        json_de::<T>
    }
}

pub struct Borsh;

impl<T: borsh::BorshDeserialize> DeserializeAs<T> for Borsh {
    fn deserializer() -> Deserializer<T> {
        borsh_de::<T>
    }
}

fn json_de<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DeserializationError> {
    serde_json::from_slice(bytes).map_err(|e| DeserializationError(e.to_string()))
}

fn borsh_de<T: borsh::BorshDeserialize>(bytes: &[u8]) -> Result<T, DeserializationError> {
    borsh::from_slice(bytes).map_err(|e| DeserializationError(e.to_string()))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{borsh_de, json_de};

    #[test]
    fn json_de__should_deserialize_valid_json() {
        // Given
        let bytes = serde_json::to_vec(&"hello").unwrap();

        // When
        let value: String = json_de(&bytes).unwrap();

        // Then
        assert_eq!(value, "hello");
    }

    #[test]
    fn json_de__should_return_error_on_invalid_json() {
        // Given
        let bytes = b"not json";

        // When
        let result = json_de::<String>(bytes);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn borsh_de__should_deserialize_valid_borsh() {
        // Given
        let bytes = borsh::to_vec(&42u64).unwrap();

        // When
        let value: u64 = borsh_de(&bytes).unwrap();

        // Then
        assert_eq!(value, 42);
    }

    #[test]
    fn borsh_de__should_return_error_on_truncated_input() {
        // Given
        let bytes = [0u8; 3];

        // When
        let result = borsh_de::<u64>(&bytes);

        // Then
        result.unwrap_err();
    }
}
