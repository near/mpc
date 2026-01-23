fn compile_project() -> (Vec<u8>, serde_json::Value) {
    let project_path = std::fs::canonicalize("./").unwrap();

    let cargo_opts = cargo_near_build::BuildOpts {
        manifest_path: Some(
            cargo_near_build::camino::Utf8PathBuf::from_path_buf(project_path.join("Cargo.toml"))
                .unwrap(),
        ),
        features: Some("abi".to_string()),
        profile: Some("release-contract".to_string()),
        ..Default::default()
    };

    let compile_artifact = cargo_near_build::build_with_cli(cargo_opts).unwrap();

    let contract_path = compile_artifact.canonicalize().unwrap();
    let wasm = std::fs::read(&contract_path).unwrap();
    let abi_path = contract_path
        .parent()
        .unwrap()
        .join("mpc_contract_abi.json");
    let abi_str = std::fs::read_to_string(abi_path).unwrap();
    let abi = serde_json::from_str::<serde_json::Value>(&abi_str).unwrap();
    (wasm, abi)
}

// this only tests that contract can be built with ABI and responds to __contract_abi
// view call
#[tokio::test]
#[ignore] // TODO(#1828): remove this once cargo-near releases a new version of cargo-near-build
async fn test_embedded_abi() -> anyhow::Result<()> {
    let (wasm, _abi) = compile_project();
    let worker = near_workspaces::sandbox().await?;
    let contract = worker.dev_deploy(&wasm).await?;

    let res = contract.view("__contract_abi").await?;

    let abi_root =
        serde_json::from_slice::<near_abi::AbiRoot>(&zstd::decode_all(&res.result[..])?)?;

    assert_eq!(abi_root.schema_version, "0.4.0");
    assert_eq!(abi_root.metadata.name, Some("mpc-contract".to_string()));

    Ok(())
}

#[test]
fn test_abi_has_not_changed() {
    let (_wasm, abi) = compile_project();
    insta::assert_json_snapshot!(abi,
        {
        ".metadata.wasm_hash" => "[WASM_HASH]",
        ".metadata.build.builder" => "[CARGO_NEAR_BUILD_VERSION]"
    });
}
