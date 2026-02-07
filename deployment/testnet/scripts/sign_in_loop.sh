#!/usr/bin/env bash
set -u

CONTRACT="mpc.barak-test-71c5.testnet"
ARGS="docs/localnet/args/sign_ecdsa.json"
SIGNER="barak_tee_test1.testnet"

ok=0
fail=0

for i in $(seq 1 100); do
  printf "Sign attempt %3d / 100 ... " "$i"

  if near contract call-function as-transaction "$CONTRACT" sign \
      file-args "$ARGS" \
      prepaid-gas '300.0 Tgas' \
      attached-deposit '100 yoctoNEAR' \
      sign-as "$SIGNER" \
      network-config testnet \
      sign-with-keychain \
      send \
      >/dev/null 2>&1
  then
    echo "PASS"
    ok=$((ok+1))
  else
    echo "FAIL"
    fail=$((fail+1))
  fi

  sleep 1
done

echo
echo "================ SUMMARY ================"
echo "Passed: $ok"
echo "Failed: $fail"
echo "========================================="
