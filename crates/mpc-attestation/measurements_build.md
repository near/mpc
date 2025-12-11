# 📘 TCB Measurements Build Guide

## 📁 Location of JSON Files
Human-readable TCB measurement JSON files live in:

```
crates/mpc-attestation/assets/
```

Typical files:

```
tcb_info.json
tcb_info_dev.json
```

You can add more files in the future (e.g., staging, additional images).  
Any file matching the prefix:

```
tcb_info*
```

will be automatically included at build time.

---

## 📄 JSON File Format
JSON format is taken directly from the MPC node's `/public_data` endpoint.

Only the following fields under:

```
tee_participant_info.Dstack.tcb_info
```

are used:

- `mrtd`
- `rtmr0`
- `rtmr1`
- `rtmr2`
- key-provider event digest (from the event log)

All other fields are ignored.

---

## ➕ Adding a New Measurements File

1. Obtain the new TCB info JSON from a node and extract the relevant section:

```bash
curl "http://<node-ip>:<port>/public_data" \
  | jq -r '.tee_participant_info.Dstack.tcb_info' \
  > crates/mpc-attestation/assets/tcb_info_new.json
```

2. Rebuild:

```bash
cargo build -p mpc-attestation
```

The build script will:

- parse the JSON files  
- extract the required measurement fields  
- decode them into fixed byte arrays  
- generate Rust constants  
- those constants will be available in the crate for attestation verification by the mpc contract  

---

## 🔧 Updating Existing Measurements
1. Modify any of the JSON files under:

```
crates/mpc-attestation/assets/
```

2. Rebuild:

```bash
cargo build -p mpc-attestation
```

---

## 🧬 Location of the Generated Measurements File

During build, Cargo generates:

```
target/debug/build/mpc-attestation-*/out/measurements_generated.rs
```

or in release mode:

```
target/release/build/mpc-attestation-*/out/measurements_generated.rs
```

Included via:

```rust
include!(concat!(env!("OUT_DIR"), "/measurements_generated.rs"));
```

This file is **auto-generated** and must **not** be committed.
