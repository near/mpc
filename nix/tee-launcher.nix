{
  buildRustBin,
}:

# tee-launcher's deps are pure Rust (rustls for TLS, tokio, clap, serde,
# ...) — no link-time C libraries beyond what the shared builder already
# arranges for (libc, plus apple-sdk_14 on darwin).

buildRustBin {
  pname = "tee-launcher";
  cargoExtraArgs = "-p tee-launcher --bin tee-launcher --locked";
  description = "Launcher binary for the MPC TEE";
}
