//! The contract's entrypoint surface, one module per feature.

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
pub mod test_utils;
