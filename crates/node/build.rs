fn main() {
    #[cfg(not(feature = "reproducible"))]
    built::write_built_file().expect("Failed to acquire build-time information");
}
