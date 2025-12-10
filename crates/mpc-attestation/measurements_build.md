# 📘 TCB Measurements Build Guide

## 📁 Location of JSON Files
TCB measurement JSON files now live in:

```
crates/mpc-attestation/assets/
```

Typical files:

```
tcb_info.json
tcb_info_dev.json
```

json format is taken directly from the node `/public_data` endpoint.

You can add more files in the future (e.g., staging, new image versions).  
Every file matching the prefix:

```
tcb_info*
```

will be automatically included at build time.

---

## 🔄 How to Update Measurements
1. Replace or edit the JSON files under:

   ```
   crates/mpc-attestation/assets/
   ```

2. Run a rebuild:

   ```bash
   cargo clean -p mpc-attestation
   cargo build -p mpc-attestation
   ```

The build script will:

- parse the JSON files  
- decode the measurements  
- generate Rust static byte arrays  
- embed them into the final WASM contract  

No runtime parsing and no JSON reading inside the contract.

---


## 🧬 Location of the Generated Measurements File
During build, Cargo produces:

```
target/debug/build/mpc-attestation-*/out/measurements_generated.rs
```

or in release mode:

```
target/release/build/mpc-attestation-*/out/measurements_generated.rs
```

This file contains:

```rust
pub const EXPECTED_MEASUREMENTS: &[ExpectedMeasurements] = &[
    ExpectedMeasurements { … },
    ExpectedMeasurements { … },
];
```

And is included into the crate via:

```rust
include!(concat!(env!("OUT_DIR"), "/measurements_generated.rs"));
```

This file is **auto-generated** and should **not be committed** to the repo.
