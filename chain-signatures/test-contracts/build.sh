#!/bin/sh
TARGET="${CARGO_TARGET_DIR:-../../target}"

cargo build --target wasm32-unknown-unknown --release
cp $TARGET/wasm32-unknown-unknown/release/mpc_test_contract.wasm ../res/
