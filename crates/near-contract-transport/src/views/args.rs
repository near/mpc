#[derive(Debug, Clone)]
pub struct ViewArgs {
    pub method_name: String,
    pub args: Vec<u8>,
}

impl ViewArgs {
    pub fn new(method_name: impl Into<String>, args: Vec<u8>) -> Self {
        Self {
            method_name: method_name.into(),
            args,
        }
    }

    /// A view call taking no arguments (an empty JSON object).
    pub fn no_args(method_name: impl Into<String>) -> Self {
        Self::new(method_name, b"{}".to_vec())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::ViewArgs;

    #[test]
    fn no_args__should_encode_an_empty_json_object() {
        assert_eq!(ViewArgs::no_args("m").args, b"{}");
    }
}
