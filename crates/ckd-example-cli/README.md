# Example CKD cli

The purpose of this tool is to show how to use the Confidential Key Derivation
(CKD) functionality in the MPC contract. The crate provides an interactive cli
that will:

- generate the parameters for a CKD request
- ask the user for the response
- verify the response
- compute the private key

The final key is derived from the CKD output with HKDF-SHA256, using a fixed
protocol-tagged salt (`near-mpc-ckd-hkdf-v1`) and a purpose-tagged `info`
(`near-mpc-ckd-strong-key-v1`). This instantiation is application-chosen and
not part of the CKD protocol; integrators deriving several keys from the same
CKD output should use a distinct `info` per key purpose.

For more details on the design and cryptography of CKD, see the
[docs](../threshold-signatures/docs/confidential_key_derivation/confidential-key-derivation.md).
The contract interface is explained in the MPC contract
[docs](../contract/README.md#submitting-a-confidential-key-derivation-ckd-request).

This cli does not cover anything related to TEE apps, as its main objective is to
show how to use the functionality in the simplest possible setting.

## Example usage

The cli takes 4 parameters:

- `signer-account-id`: the account that will be used to call the MPC contract.
  Notice the secret obtained at the end is dependent on this value and the derivation path, the same
  account and derivation path will always obtain the same secret.

- `domain-id`: the domain id in the MPC contract that supports CKD. The associated scheme of such
domain is `Bls12381`.

- `mpc-ckd-public-key`: the public key associated to the domain id above.

- `derivation-path`: derivation path for the confidential key, which allows a single account to request several keys

Notice that both the latter two parameters can be obtained by querying the state
of the MPC contract.

```console
❯ cargo run -p ckd-example-cli -- --domain-id 2 --signer-account-id frodo.test.near --derivation-path "mykey" --mpc-ckd-public-key bls12381g2:25sFv4K1oJxLxY3t1s6oPWXUx9nEq6a5LjDg8Gajp5NjaHoTq5Dm3CNXmmbnGHsWHjLQ1RRvZ3z8By6TMU8TWexXjwDvqefnpCMTPAEiFiCZ2cDZypBRoskefLrLeFq35Mx5

Call the function request_app_private_key with parameters:
{"request":{"app_public_key":{"AppPublicKey":"bls12381g1:67UMHEnqJCvuBv44ecVtcoE7ES2vNvAnvh72DhEkvChw1cjQ7L4Ybt8KJdHqSdXoNz"},"derivation_path":"mykey","domain_id":2}}
Please enter a the response in json format (for example {"big_c": "bls12381g1:...","big_y": "bls12381g1:..."}):
Your response: {
  "big_c": "bls12381g1:7EuSqCZYRQFoQ75kUA1J1TUvCDv8CKGAbhw152UDnJivg2F4epZpzns6GGjHcTFjjD",
  "big_y": "bls12381g1:5jZD2vmFZRDnNZiiWjcxYLGWXDj1GBwQVnymraPo7GVbw4bxhZgffZrSkM83DyyT1T"
}
The key is: 4531c3a97b71ac96a63946f759c769aecff53b9f95e6f806166c0c6c6971877e
```

### Publicly verifiable variant

By passing the `--publicly-verifiable` flag, the CLI generates an ephemeral key
pair on both G1 and G2 (`a·G1`, `a·G2`) and uses `AppPublicKeyPV` in the
request. This allows the contract to verify the CKD response on-chain.

```console
❯ cargo run -p ckd-example-cli -- --domain-id 2 --signer-account-id frodo.test.near --derivation-path "mykey" --mpc-ckd-public-key bls12381g2:25sFv4K1oJxLxY3t1s6oPWXUx9nEq6a5LjDg8Gajp5NjaHoTq5Dm3CNXmmbnGHsWHjLQ1RRvZ3z8By6TMU8TWexXjwDvqefnpCMTPAEiFiCZ2cDZypBRoskefLrLeFq35Mx5 --publicly-verifiable

Call the function request_app_private_key with parameters:
{"request":{"derivation_path":"mykey","app_public_key":{"AppPublicKeyPV":{"pk1":"bls12381g1:...","pk2":"bls12381g2:..."}},"domain_id":2}}
Please enter a the response in json format (for example {"big_c": "bls12381g1:...","big_y": "bls12381g1:..."}):
Your response: {"big_c": "bls12381g1:...","big_y": "bls12381g1:..."}
The key is: ...
```

### Deterministic output

If the tool is used again, it will generate a different `app_public_key`, but obtain the same key at the end.

```console
❯ cargo run -p ckd-example-cli -- --domain-id 2 --signer-account-id frodo.test.near --derivation-path "mykey" --mpc-ckd-public-key bls12381g2:25sFv4K1oJxLxY3t1s6oPWXUx9nEq6a5LjDg8Gajp5NjaHoTq5Dm3CNXmmbnGHsWHjLQ1RRvZ3z8By6TMU8TWexXjwDvqefnpCMTPAEiFiCZ2cDZypBRoskefLrLeFq35Mx5

Call the function request_app_private_key with parameters:
{"request":{"app_public_key":{"AppPublicKey":"bls12381g1:7LEuvPK3kiQXi9PFUF6jggPEexE6BZACH6HrFnhE6GWBB1mKbfZLTNUJzoMZnZ2Zxb"},"derivation_path":"mykey","domain_id":2}}
Please enter a the response in json format (for example {"big_c": "bls12381g1:...","big_y": "bls12381g1:..."}):
Your response: {
  "big_c": "bls12381g1:71QTA7N8JbTmn5UxhXRZdAe2NnSGSwsmzqavZAoKjuW1h9Ff7M855ExY5GX4t9MDiH",
  "big_y": "bls12381g1:64E4rRZr4wjwdpU5L8XfFNPer2qYThHGzfkn6WBzszAzosTN5AeS4H5H9XX8KfiXvY"
}
The key is: 4531c3a97b71ac96a63946f759c769aecff53b9f95e6f806166c0c6c6971877e
```
