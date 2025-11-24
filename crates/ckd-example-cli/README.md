# Example CKD cli

The purpose of this tool is to show how to use the CKD functionality in the MPC
contract. The crate provides an interactive cli that will:

- generate the parameters for a CKD request
- ask for the response
- verify the response
- compute the private key

## Example usage

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
