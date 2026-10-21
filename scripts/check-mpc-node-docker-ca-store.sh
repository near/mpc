#!/usr/bin/env bash
# Checks that the node image's CA store rejects certificates issued by the six
# compromised eMudhra TLS intermediates (RUSTSEC-2026-0382) on both trust paths:
#   leaf -> EM <DV|OV|EV> TLS CA - <G3B|G3C> -> emSign Root TLS CA - G3 -> emSign ECC Root CA - G3
#   leaf -> EM <DV|OV|EV> TLS CA - <G3B|G3C> (cross-signed) -> AAA Certificate Services
# Each leaf was minted with the leaked key of its intermediate for example.com,
# so an unpatched image accepts it.
#
# Usage: NODE_IMAGE_NAME=<image> scripts/check-mpc-node-docker-ca-store.sh

set -euo pipefail

FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ca-store-fixtures"
: "${NODE_IMAGE_NAME:=mpc-node}"

# Runs inside the image, with its own OpenSSL and SSL_CERT_FILE.
docker run --rm -v "$FIXTURES:/fixtures:ro" --entrypoint sh "$NODE_IMAGE_NAME" -eu -c '
cd /fixtures
# $1: label, $2: distrusted root, $3: untrusted chain, $4: leaf, $5...: image store args
check() {
  label=$1 root=$2 chain=$3 leaf=$4; shift 4
  # A rejection only counts if the chain validates when its root is trusted.
  openssl verify -CAfile "$root" -untrusted "$chain" "$leaf" >/dev/null 2>&1 \
    || { echo "$label: control failed, bad fixture"; exit 1; }
  if openssl verify -show_chain "$@" -untrusted "$chain" "$leaf" >/tmp/out 2>&1; then
    echo "$label: image trusts the forged certificate"; cat /tmp/out; exit 1
  fi
  echo "$label: rejected"
}
for ca in dv-g3b dv-g3c ov-g3b ov-g3c ev-g3b ev-g3c; do
  # Bundle file: read by OpenSSL/native-tls via SSL_CERT_FILE. Hashed dir: rustls-native-certs fallback.
  for store in "-CAfile $SSL_CERT_FILE" "-no-CAfile -CApath /etc/ssl/certs"; do
    check "$ca emSign path [$store]" distrusted-root-emsign-ecc-g3.pem \
      "$ca/chain-via-emsign-ecc-root-g3.pem" "$ca/forged-leaf.pem" $store
    check "$ca AAA path [$store]" distrusted-root-aaa.pem \
      "$ca/chain-via-aaa-certificate-services.pem" "$ca/forged-leaf.pem" $store
  done
done
echo "Node image CA store rejects all six compromised eMudhra TLS intermediates"
'
