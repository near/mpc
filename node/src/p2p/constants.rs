/// We hardcode a dummy private key used for signing certificates. This is
/// fine because we're not relying on a certificate authority to verify
/// public keys; rather the public keys come from the contract on chain.
/// Still, TLS requires us to have signed certificates, so this is just to
/// satisfy the TLS protocol.
pub(crate) const DUMMY_ISSUER_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIGkMPQEb0GXxgFXbgojLebmHnCUpS3QYqJrYcfyFqHtW
gSEAAbdC8KDpDZPqZalKndJm2N6EXn+cNxIb2gRa21P5mcs=
-----END PRIVATE KEY-----";

pub(crate) const PKCS8_HEADER: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

pub(crate) const PKCS8_MIDDLE: [u8; 3] = [0x81, 0x21, 0x00];
