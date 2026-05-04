# TON fixtures

These JSON files are inputs for `tests/ton_inspector.rs`. Each is a raw
`GET /api/v3/transactions?account=<addr>&hash=<tx-hash>&include_msgs=true&limit=1`
response from toncenter v3, served back to the inspector via `httpmock` to
exercise the full `TonInspector → ReqwestTonClient → HTTP → DTO →
normalize_body_boc → TonLog` path end to end.

The `hash` query parameter accepts either lowercase hex or base64; the
inspector currently sends lowercase hex (it owns the raw 32 bytes), while
toncenter consistently *returns* base64 in the response body — that is why
the recapture command below uses base64 (it is what an explorer UI hands you
when you copy a tx hash).

| File | Origin | Shape | Why it's here |
|---|---|---|---|
| `simple_no_refs.json` | TON **mainnet** tx `0:A11802E9…:lnQss6nQ…` (mc_block_seqno 62511761) | ext-out, byte-aligned body, `op = 0x0000000a`, **0 refs** | Exercises the no-refs happy path with a real toncenter response shape. |
| `event_with_ref.json` | TON **mainnet** tx `0:CEFEF6CB…:etVK0OK0…` (mc_block_seqno 62511957) | ext-out, byte-aligned body, `op = 0x9c610de3`, **1 ref** | Exercises the ref-carrying happy path on a real production contract. |
| `synthetic_init_transfer.json` | **Hand-crafted** via `pytoniq-core` | omni-bridge `InitTransferEvent`-shaped body: `op = 0x99000001`, **2 refs** (recipient + message strings) | The omni-bridge TON contracts are not yet deployed to mainnet (they are the reason this work exists), so we cannot capture a real fixture for the `0x99000001` / `0x99000002` op codes called out in the task brief. This fixture mirrors the expected on-wire shape so we can regression-test the multi-ref path against the same code that serves production. |

## Re-capture procedure

If toncenter changes its response envelope, re-capture via:

```bash
# Mainnet, per-hash endpoint (base64 form here; the inspector itself queries
# the equivalent lowercase-hex form — toncenter accepts either).
ACC='0%3AA11802E9D7001AF100C1AF89AB361D43209CCCCAF1B60AAB01F120FD0C345DE9'
HASH='lnQss6nQ108972CH3hQ4WgMeoqPuh2xOEG1ChKus2VQ%3D'
curl -sS "https://toncenter.com/api/v3/transactions?account=${ACC}&hash=${HASH}&include_msgs=true&limit=1" \
  | python3 -m json.tool > simple_no_refs.json
```

(URL-encode `:` as `%3A` and `+` / `/` / `=` in the base64 hash as `%2B` / `%2F`
/ `%3D`.)

Replace `synthetic_init_transfer.json` with a real capture once the omni-bridge
TON contracts deploy to a public network — at that point update the **Origin**
column above with the real tx hash and network.

## Determinism note

The assertions in `ton_inspector.rs` compare `body_bits` byte-for-byte but
compare `body_refs` **structurally** (parse each ref back through
`BagOfCells::parse` and compare the inner cell's bit count, data, and ref
count). This is because `tonlib-core` and `pytoniq-core` may serialize the same
cell tree with slightly different BoC envelope flags; structural comparison
asserts the cell tree identity while tolerating envelope drift.
