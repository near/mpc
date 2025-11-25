# Example CKD cli

The purpose of this tool is to show how to use the Confidential Key Derivation
(CKD) functionality in the MPC contract. The crate provides an interactive cli
that will:

- generate the parameters for a CKD request
- ask the user for the response
- verify the response
- compute the private key

For more details on the design and cryptography of CKD, see the
[docs](https://github.com/near/threshold-signatures/blob/main/docs/confidential_key_derivation/confidential_key_derivation.md).
The contract interface is explained in the MPC contract
[docs](https://github.com/near/mpc/blob/main/crates/contract/README.md#submitting-a-confidential-key-derivation-ckd-request).

This cli does not cover anything related to TEE apps, as it main objective is to
show how to use the functionality in the simplest possible setting.

## Example usage

The cli takes 3 parameters:

- `signer-account-id`: the account that will be used to call the MPC contract.
  Notice the secret obtained at the end is dependent on this value, the same
  account will always obtain the same secret.

- `domain-id`: the domain id in the MPC contract that supports CKD. The associated scheme of such
domain is `Bls12381`.

- `mpc-ckd-public-key`: the public key associated to the domain id above.

Notice that both the latter two parameters can be obtained by querying the state
of the MPC contract.

```console
❯ cargo run -p ckd-example-cli -- --domain-id 2 --signer-account-id frodo.test.near --mpc-ckd-public-key bls12381g2:22AgdyBXAQor5kiToW4frjEksuAhyic1S7CWWX7LFBTXFt1MxjcXwuB73yFCQVQfwMjKQoFFtmxPSUg2fCjhNUNVCFPVdtotAFMkPpoDg9s3QWQSZ2gUfvS3Uw1gaESFCfrw

Call the function request_app_private_key with parameters:
{"request":{"app_public_key":"bls12381g1:64PJdGWrTzm5HY7wkXxWWPdaa6rtadsRuz4DxpZKK6nAVFE8xDPrQBLNbApfWM45ar","domain_id":2}}
Please enter a the response in json format (for example {"big_c": "bls12381g1:...","big_y": "bls12381g1:..."}):
Your response: {
  "big_c": "bls12381g1:5qzsECuw1B4oCG78dUwJQ49o5egkNBfPvGfcJLKbznEeL7fpEv4hZYyu9VRt64ucRz",
  "big_y": "bls12381g1:5n8Y21i4RMN7ydvDkXVPL5StUG4jkfz31sT8jW8HtJ6JaY5Vt34fsTSP443wGmXFP8"
}
The key is: bc73293faedf534d8028d575bcf9cf5455ffe5f468882928305be9d2be2e838d
```

If the tool is used again, it will generate a different `app_public_key`, but obtain the same key at the end.

```console
❯ cargo run -p ckd-example-cli -- --domain-id 2 --signer-account-id frodo.test.near --mpc-ckd-public-key bls12381g2:22AgdyBXAQor5kiToW4frjEksuAhyic1S7CWWX7LFBTXFt1MxjcXwuB73yFCQVQfwMjKQoFFtmxPSUg2fCjhNUNVCFPVdtotAFMkPpoDg9s3QWQSZ2gUfvS3Uw1gaESFCfrw

Call the function request_app_private_key with parameters:
{"request":{"app_public_key":"bls12381g1:5ieM9Vog2JyWnTsHjh2eEMMZzHae8BcGXmdtrgjqkjBDWSSGY2ndv7dRQhGEiZ9BvB","domain_id":2}}
Please enter a the response in json format (for example {"big_c": "bls12381g1:...","big_y": "bls12381g1:..."}):
Your response: {
  "big_c": "bls12381g1:6AZZQCerkTtGxV7J3AQuzSdghn2uUim41m88hL4NHdxn7GT8GjdBzZ2fGe6WbVkZGS",
  "big_y": "bls12381g1:633sY8TsRrW3Fd6bZn3GRCVyt5qGBVAtDHcibBPTzVPwEmM6zKwciqZN2LakQzAV4J"
}
The key is: bc73293faedf534d8028d575bcf9cf5455ffe5f468882928305be9d2be2e838d
```
