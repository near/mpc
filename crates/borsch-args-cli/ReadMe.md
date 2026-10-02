# borsh-args-cli

Decodes a borsh-encoded contract-call argument file into display format useful to read.

### Usage

```bash
borsh-args-cli --type <TYPE> --file <path-to-file>.borsh
````
or, if you were handed a base64 string instead of a file
```bash
borsh-args-cli --type <TYPE> --base64 <base64-string>
```

`--type` is one of:
- `propose-update-args`
- `verify-quote-args`
- `foreign-chain-provider-votes`

A wrong `--type` (or a corrupt/truncated file) fails loudly rather than silently.

### Adding a new type

Add a variant to `ArgType` in `src/types.rs` and one match arm calling
`decode::<Type>(bytes)`, where `Type` implements `BorshDeserialize`
and `serde::Serialize`. Then adjust to appropriate display, if applicable.