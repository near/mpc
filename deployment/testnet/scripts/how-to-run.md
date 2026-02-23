# Running `scale-testnet-tee.sh`

This document explains how to run the `scale-testnet-tee.sh` script:
- From scratch (new network)
- From specific phases
- For scaling an existing network
- With a clear list of environment variables

---

## Where to run the script

Run from the **repository root**:

```bash
bash deployment/testnet/scripts/scale-testnet-tee.sh
```

The script relies on repo-relative paths and should not be run from inside the `scripts/` directory.

---

## Phase model (important)

The script is **phase-gated**. Execution starts at `START_FROM_PHASE` and runs forward.

Defined phases (in order):

```
preflight
render
near_accounts
near_nodes
near_contract
deploy
collect
init_args
near_keys
near_init
near_vote_hash
near_vote_domain
near_vote_new_params
near_vote_new_params_votes
```

Special value:
- `auto` – automatically determine start phase based on existing artifacts

---

## Environment variables

### Required (always)

```bash
export MPC_NETWORK_BASE_NAME=barak-test
export N=6
export BASE_PATH=/mnt/data/barak/dstack
export MPC_IMAGE_TAGS=3.3.0
```

---

### Accounts & funding (recommended)

```bash
export ACCOUNT_MODE=subaccounts
export FUNDER_ACCOUNT=<funded-account>.testnet
```

Balances (safe defaults for up to ~10 nodes):

```bash
export ROOT_INITIAL_BALANCE="20 NEAR"
export CONTRACT_INITIAL_BALANCE="16 NEAR"
export NODE_INITIAL_BALANCE="0.3 NEAR"
export MAX_NODES_TO_FUND=10
```

---

### NEAR reliability / stability

```bash
export NEAR_CLI_DISABLE_SPINNER=1
export NEAR_TX_SLEEP_SEC=5
export NEAR_RETRY_MAX=6
export NEAR_RETRY_SLEEP_SEC=15
export NEAR_RETRY_BACKOFF_MULT=2
```

Recommended RPC:
```
https://test.rpc.fastnear.com
```

---

### Flow control

```bash
export START_FROM_PHASE=auto
export STOP_AFTER_PHASE=
export RESUME=1
export NO_PAUSE=0
```

Notes:
- `RESUME=1` reuses existing artifacts
- `RESUME=0` forces a clean run
- `NO_PAUSE=0` pauses between phases (ENTER to continue)
- `NO_PAUSE=1` runs non-interactively

---

## Run scenarios

---

## 1. Run from scratch (new network)

```bash
export MPC_NETWORK_BASE_NAME=barak-test
export N=6
export BASE_PATH=/mnt/data/barak/dstack
export MPC_IMAGE_TAGS=3.3.0

export ACCOUNT_MODE=subaccounts
export FUNDER_ACCOUNT=barak_tee_test1.testnet

export ROOT_INITIAL_BALANCE="20 NEAR"
export CONTRACT_INITIAL_BALANCE="16 NEAR"
export NODE_INITIAL_BALANCE="0.3 NEAR"
export MAX_NODES_TO_FUND=10

export NEAR_CLI_DISABLE_SPINNER=1
export NEAR_TX_SLEEP_SEC=5

export RESUME=0
export NO_PAUSE=0

bash deployment/testnet/scripts/scale-testnet-tee.sh
```

---

## 2. Resume a failed run automatically

```bash
export RESUME=1
export START_FROM_PHASE=auto

bash deployment/testnet/scripts/scale-testnet-tee.sh
```

---

## 3. Start from a specific phase

Example: restart from key collection

```bash
export START_FROM_PHASE=collect
export RESUME=1

bash deployment/testnet/scripts/scale-testnet-tee.sh
```

---

## 4. Run only one phase (start + stop)

Example: only add keys to accounts

```bash
export START_FROM_PHASE=near_keys
export STOP_AFTER_PHASE=near_keys

bash deployment/testnet/scripts/scale-testnet-tee.sh
```

---

## 5. Scale an existing network (add nodes)

Example: scale from 6 → 10 nodes by adding 4.

```bash
export MPC_NETWORK_BASE_NAME=barak-test
export REUSE_NETWORK_NAME=barak-test-71c5
export N=10
export BASE_PATH=/mnt/data/barak/dstack
export MPC_IMAGE_TAGS=3.3.0

export ACCOUNT_MODE=subaccounts
export FUNDER_ACCOUNT=barak_tee_test1.testnet

export ADD_NODES=4
export START_FROM_PHASE=near_vote_new_params

export NEAR_CLI_DISABLE_SPINNER=1
export NEAR_TX_SLEEP_SEC=5
export NO_PAUSE=0

bash deployment/testnet/scripts/scale-testnet-tee.sh
```

---

## 6. Resume voting only (votes phase)

Use this if `vote_new_parameters.json` already exists and all nodes are synced.

```bash
export MPC_NETWORK_BASE_NAME=barak-test
export REUSE_NETWORK_NAME=barak-test-71c5
export N=10
export BASE_PATH=/mnt/data/barak/dstack
export MPC_IMAGE_TAGS=3.3.0

export ACCOUNT_MODE=subaccounts
export FUNDER_ACCOUNT=barak_tee_test1.testnet

export START_FROM_PHASE=near_vote_new_params_votes
export STOP_AFTER_PHASE=near_vote_new_params_votes

export NEAR_CLI_DISABLE_SPINNER=1
export NEAR_TX_SLEEP_SEC=5
export NO_PAUSE=0

bash deployment/testnet/scripts/scale-testnet-tee.sh
```

---

## Validation commands

### Check contract state

```bash
near contract call-function as-read-only mpc.<network>.testnet state json-args '{}' network-config testnet now
```

### Check node keys endpoint

```bash
curl http://<node-ip>:<port>/public_data
```

### Check node debug tasks

```bash
curl http://<node-ip>:<port>/debug/tasks
```

---

## Notes & caveats

- The contract **must be in `Running` state** to vote new parameters
- If the contract is already in `Resharing`, scaling is intentionally blocked
- 10-node clusters are resource heavy and may cause triple-generation timeouts
- Restarting all nodes once may be required after initial deployment
