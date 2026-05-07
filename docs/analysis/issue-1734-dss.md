# Issue #1734 — DSS not working in TEE CVM mode: analysis

Issue: https://github.com/near/mpc/issues/1734

> **Status: root cause confirmed and fix validated end-to-end on bare neard
> AND through a full TDX CVM** (PR #3145 — launcher TOML plumbing for
> `tier3_public_addr` and `external_storage_fallback_threshold`). The bug is
> **not CVM-specific** — it's host-level, triggered by any host with
> multiple IPs where `:24567` is bound to a non-default IP.

## TL;DR

- **Bug:** DSS state-sync times out on Bob's testnet TEE node. nearcore
  advertises the wrong IP for peers to send Tier3 responses to. Caused by
  Bob's multi-IP host topology — outbound traffic egresses on a different
  IP than the one `:24567` is bound to, so auto-discovery picks the wrong
  one.
- **Scope:** only affects hosts with multiple public IPs on one NIC
  (Bob, Alice — OVH bare-metal). **Mainnet GCP node is not affected**
  (verified — single external IP, auto-discovery correct).
- **Fix:** set `network.experimental.tier3_public_addr = "<bound_ip>:24567"`
  in the neard config. Validated on Alice end-to-end — both on bare neard
  (DSS recovered within seconds) and through a full TDX CVM with
  PR #3145's launcher TOML plumbing (96% DSS success rate, 13–29 Tier3
  inbound connections from real testnet peers).
- **Also remove** the hardcoded `external_storage_fallback_threshold = 0`
  in `deployment/start.sh:46`, which forced bucket-only sync and had been
  masking this bug for every MPC node since launch.
- **Action on Bob:** apply both via the dstack-vmm "Update VM Config" flow
  (per the runbook in mpc-private PR #304), then Shutdown → Start.
- **Tier2 inbound peers** (separate symptom, also caused by the same
  topology) appear to need much longer than our test windows to recover
  via gossip. Test 6 confirmed even fixing the gossiped `PeerInfo` (via
  Option 3b) doesn't bring inbound peers within 30 min, and Option 0's
  Test 5 ran 1.5+ days with the same result. The MPC node functions
  fine without it (see "Does the MPC node actually need inbound Tier2?"
  in the body), so this is hygiene/network-citizenship — not a blocker.

## Summary

- **Symptom on Bob's testnet TEE node:** all DSS state-sync attempts time out.
- **Root cause:** nearcore auto-discovers `my_public_addr` from the IP that
  peers observe when *we* connect to them. On hosts with multiple public
  IPs on one NIC (Bob, Alice), outbound traffic egresses with the dynamic
  IP set by the default route, but `:24567` is bound to a different static
  IP. Peers tell us "we see you at `<outbound_ip>:24567`", we believe them,
  and we tell the network to deliver Tier3 state parts there — where
  nothing is listening.
- **Scope of impact:** only hosts with this multi-IP topology. The mainnet
  GCP node is **not affected** (verified — `tier3_public_addr` correctly
  set to its actual public IP, 9 inbound Tier2 peers, all healthy). See
  [Scope of impact](#scope-of-impact) for the full breakdown.
- **The bug had been masked** by `deployment/start.sh:46` hardcoding
  `external_storage_fallback_threshold = 0`, which made every non-localnet
  MPC node bucket-sync only. Bucket sync is being deprecated; once disabled,
  this latent bug surfaced.
- **Fix:** set `network.experimental.tier3_public_addr` in `config.json` to
  `<bound_ip>:24567`. Validated on Alice — DSS recovered immediately.
- **Caveat:** `tier3_public_addr` fixes Tier3 (state sync) only. The
  separate "zero inbound peers" symptom — peers gossiping our wrong
  `PeerInfo` and failing to connect — needs a different fix (binding on
  `0.0.0.0` or per-process source-IP routing). Out of scope for this issue.

## Reproduction and validation (run 2026-05-05 on Alice)

### Test 1 — observe Bob's running testnet TEE node

```bash
curl -s http://46.105.87.136:8080/metrics | \
  grep -E "near_tier3_public_addr|near_peer_connections|near_block_height_head"
```

| Probe | Result |
|---|---|
| `near_tier3_public_addr{addr="…"}` | `91.134.92.20:24567` |
| Public IP for the CVM (where everything else binds) | `46.105.87.136` |
| TCP `46.105.87.136:24567` from a remote host | OPEN |
| TCP `91.134.92.20:24567` from a remote host | Connection refused |
| `PeerManagerActor::handle tier3 request` count | 240 — Tier3 *outbound* fine |
| `near_peer_connections{peer_type="Outbound",tier="T2"}` | 34 |
| `near_peer_connections{peer_type="Inbound",…}` | (no line — i.e. 0) |

Bob's network state confirmed the asymmetric-IP shape:

```text
ss -ltn | grep ':24567'
LISTEN 0  1  46.105.87.136:24567   0.0.0.0:*   ← bound to one specific IP, not 0.0.0.0

ip route get 8.8.8.8
8.8.8.8 via 100.64.0.1 dev ens49f0np0 src 91.134.92.20   ← outbound exits as a different IP
```

### Test 2 — reproduce on Alice with bare `neard`, no CVM/docker

Alice has the same multi-IP topology (`51.68.219.{1..14}` static + dynamic
`57.129.140.254` as the default-route source). Steps:

```bash
HOME_DIR=/mnt/data/barak/testnet-dss
mkdir -p $HOME_DIR
neard --home $HOME_DIR init --chain-id testnet --download-genesis --download-config

# Patch: bind P2P to one specific static IP, force DSS, track shard 5
BOOT_NODES=$(curl -s -X POST https://rpc.testnet.near.org \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"network_info","params":[],"id":"x"}' \
  | jq -r '.result.active_peers[] | "\(.id)@\(.addr)"' \
  | awk -F'@' '!seen[$2]++ {print $0}' | paste -sd',' -)

jq --arg bn "$BOOT_NODES" '
  .network.addr = "51.68.219.13:24567"
  | .rpc.addr = "0.0.0.0:13030"
  | del(.state_sync)
  | .state_sync_enabled = true
  | .network.boot_nodes = $bn
  | .tracked_shards_config = {"Accounts": ["v1.signer-prod.testnet"]}
' $HOME_DIR/config.json > /tmp/c.json && mv /tmp/c.json $HOME_DIR/config.json

nohup neard --home $HOME_DIR run > $HOME_DIR/neard.log 2>&1 &
```

Within ~1 minute, every Bob symptom reproduced:

| Metric | Result on Alice (bare neard) |
|---|---|
| `near_tier3_public_addr{addr="…"}` | `57.129.140.254:24567` (the *outbound* IP, not the bound `51.68.219.13`) |
| `near_peer_connections{peer_type="Outbound",tier="T2"}` | 18 |
| `near_peer_connections{peer_type="Inbound",…}` | (none) |

After ~5 minutes (when state sync started, tracking shard 5):

| Metric | Result |
|---|---|
| `near_state_sync_download_result{result="timeout",shard_id="5",source="network",type="header"}` | climbing — 102 by ~25 min in |
| `near_block_height_head` | stuck at `42376888` (state sync not progressing) |
| `near_sync_status` | `5` (state sync) |

And the explicit nearcore warning fired in the log:

> "state sync header retrieval is failing repeatedly. This may indicate a
> Tier3 connectivity issue - peers cannot connect back to deliver state
> data. Check: (1) the node's listening port is open for inbound TCP,
> (2) if behind NAT, set `network.experimental.tier3_public_addr` in
> `config.json`."

That's reproduction without docker, without dstack, without QEMU, without
any CVM stack — just `neard` 2.11.0 on a multi-IP host.

### Test 3 — apply the fix and verify DSS recovers

```bash
kill $(cat $HOME_DIR/neard.pid)
jq '.network.experimental.tier3_public_addr = "51.68.219.13:24567"' \
  $HOME_DIR/config.json > /tmp/c.json && mv /tmp/c.json $HOME_DIR/config.json
nohup neard --home $HOME_DIR run > $HOME_DIR/neard.log 2>&1 &
```

Within ~15 seconds:

| Metric | Before fix | After fix |
|---|---|---|
| `near_tier3_public_addr{addr="…"}` | `57.129.140.254:24567` | **`51.68.219.13:24567`** |
| `near_state_sync_download_result{result="success",source="network",type="header"}` | 0 | 1 |
| `near_state_sync_download_result{result="success",source="network",type="part"}` | 0 | 14 |
| `near_peer_connections{peer_type="Inbound",tier="T3"}` | (none) | 12 |

Fix confirmed — DSS state parts started flowing. T3 inbound connections
landing as expected (responder peers connecting back to deliver state).

Note: `near_peer_connections{peer_type="Inbound",tier="T2"}` remained
absent. `tier3_public_addr` does not influence what peers gossip about us
via `PeerInfo`, so regular Tier2 inbound from arbitrary peers continues to
fail — peers still try the wrong IP they learned via gossip. **Separate
problem; does not block DSS.**

### Test 4 — confirm a healthy node on different topology (mainnet, GCP)

Sanity check: does the bug actually require the multi-IP host topology, or
does it affect any node? The mainnet MPC node runs on a GCP VM
(`multichain-mainnet-0.nearone.org`, public IP `34.22.198.39`). Probed its
metrics:

| Probe | Result |
|---|---|
| `dig multichain-mainnet-0.nearone.org` | `34.22.198.39` |
| `near_tier3_public_addr{addr="…"}` | **`34.22.198.39:24567`** ✅ matches |
| TCP `34.22.198.39:24567` | OPEN ✅ |
| `near_peer_connections{peer_type="Inbound",tier="T2"}` | **9** ✅ (none on Bob/Alice) |
| `near_peer_connections{peer_type="Outbound",tier="T2"}` | 28 |
| `near_sync_status` | 0 (caught up; no recent state sync to test against) |

The mainnet node has the **correct** auto-discovered address and **9 real
inbound Tier2 peers** — none of Bob's symptoms. This confirms the bug is
specific to the multi-IP / asymmetric-routing host topology, not a defect
in mpc-node, neard, or DSS itself.

Why GCP works: a standard GCP VM has one internal IP on the NIC mapped via
**1:1 NAT** to one external IP. Outbound source IP (as observed by peers)
= inbound destination IP = the same external IP. Auto-discovery's
"egress IP = ingress IP" assumption holds. The OVH bare-metal hosts
Bob/Alice violate that assumption by exposing many IPs directly on one NIC
and selecting outbound source via the default route.

### Validation coverage — what's been tested vs. what hasn't

**Tested ✅**

- **Bug reproduces** on bare neard 2.11.0 with multi-IP host (Test 2).
- **`tier3_public_addr` fixes DSS** on bare neard when set directly in
  `config.json` (Test 3).
- **GCP single-IP topology is healthy** without any fix (Test 4).
- **End-to-end through the TDX/launcher chain** (Test 5). PR #3145's
  `tier3_public_addr` and `external_storage_fallback_threshold` fields
  flow correctly from launcher TOML → `patch_near_config` → neard config
  inside the CVM, and DSS state sync works through the full QEMU /
  dstack / docker network stack.
- **Option 3b (per-host SNAT) alone is sufficient for DSS** (Test 6).
  No node config or code changes; iptables SNAT on `--dport 24567`.
  State sync completed faster than Option 0 (~32 min vs ~55 min).
  Caveat: SNAT rule must be in place before neard's first peer
  connections, otherwise conntrack pins the pre-SNAT mapping and
  auto-discovery latches onto the wrong IP.

**Not yet tested ❌**

- **Options 2 / 3a / 5** of the host-level fix list. None empirically
  validated. We have empirical confirmation only for the leading
  candidate (Option 3b — see Test 6) and Option 0.
- **Tier2 inbound recovery on long timescales.** Both Option 0
  (Test 5, ran 1.5+ days) and Option 3b (Test 6, 32 min) ended with
  zero Tier2 inbound peers. Either it takes much longer than these
  windows, or it needs a separate fix entirely. The MPC node functions
  fine without it (see "Does the MPC node actually need inbound
  Tier2?"), so this is a hygiene follow-up.

### Test 5 — full TDX CVM with PR #3145 (run 2026-05-06 on Alice)

Validates the entire fix pipeline against a real testnet TDX CVM:

```
launcher TOML (tier3_public_addr, external_storage_fallback_threshold)
  ↓
launcher's intercept_node_config → mpc-config.toml on shared volume
  ↓
mpc-node's StartConfig::from_toml_file → patch_near_config (PR #3145)
  ↓
neard config.json
  (network.experimental.tier3_public_addr +
   state_sync.sync.ExternalStorage.external_storage_fallback_threshold)
  ↓
neard at runtime → near_tier3_public_addr metric
  ↓
peers send Tier3 state-sync responses → host port-forward → QEMU slirp
                                      → docker bridge → neard inside CVM
```

Setup:
- Custom mpc-node image built from PR #3145 branch (CI), tag
  `barak-testing-dss-tier3-public-addr-c371677`,
  manifest `sha256:7210432270b0d05f62cae03074feb51575d4b28feeceae525fe068935020f206`.
- Launcher image `nearone/mpc-launcher:main-c0778dc` (latest main, supports
  the current TOML schema with `image_reference`).
- Testnet TDX CVM on Alice, dstack-dev-0.5.8, SGX local key provider.
- TOML fields under test:
  ```toml
  [mpc_node_config.near_init]
  tier3_public_addr = "51.68.219.13:24567"
  external_storage_fallback_threshold = 1000
  ```
- Bound to a single static IP (`51.68.219.13:24567`), mirroring Bob's
  setup so the bug would reproduce in the unfixed case.
- Script: `localnet/tee/scripts/rust-launcher/single-node-testnet.sh`.

**mpc-node startup logs** (all timestamps from the same boot):

```
INFO mpc_node::run: mpc-node 3.9.0 (release 3.9.0) (commit c371677)   ← PR #3145 branch
INFO mpc_node::run: starting MPC node account_id=dss-test.testnet
                    contract_id=v1.signer-prod.testnet home_dir=/data
INFO mpc_node::run: TEE config tee_authority=dstack
                    image_hash=sha256:7210432...020f206
INFO mpc_node::run: NEAR init config chain_id=testnet download_genesis=true
INFO mpc_node::run: TEE attestation generated successfully
...
INFO stats: node_status="State 8qYjL...[5: parts] (5 downloads, 0 computations)
                        11 peers ⬇ 319 kB/s ⬆ 28.9 kB/s ..."
```

**Final metrics — state sync completed via DSS (~55 min total):**

```
near_tier3_public_addr{addr="51.68.219.13:24567"} 1
near_block_height_head 249010656                           ← jumped from 42376888 to testnet tip ✅

near_peer_connections{peer_type="Outbound",tier="T2"} 13
# (Inbound,T3 = 0 between transfers — Tier3 is ephemeral by design)

near_state_sync_download_result{result="success",
   shard_id="5", source="network", type="header"} 1
near_state_sync_download_result{result="success",
   shard_id="5", source="network", type="part"} 1019       ← 96.3% success rate
near_state_sync_download_result{result="timeout",
   shard_id="5", source="network", type="part"} 37
near_state_sync_download_result{result="sender_dropped",
   shard_id="5", source="network", type="part"} 2
# Total parts: 1058 — 1019 success, 39 transient failures (retried successfully)
# Critically: ZERO source="external" entries — no bucket fallbacks

near_sync_status 0                                         ← NoSync (caught up) ✅
near_sync_requirements_current{state="AlreadyCaughtUp"} 1
near_sync_requirements_total{state="AlreadyCaughtUp"} 18   ← multiple sync cycles all completed
```

**Tier3 disconnect warnings** also observed in the log:

```
WARN network: received message on connection, disconnecting
              msg_variant=Disconnect tier=T3
```

These look concerning at first read but are normal Tier3 lifecycle —
nearcore explicitly designs Tier3 connections as ephemeral: peer opens
TCP, sends one state part, sends Disconnect, both sides close (from
`chain/network/src/tcp.rs`'s `Tier::T3` doc: *"Tier3 connections are
created ad hoc to directly transfer large messages... we avoid delaying
other messages and we minimize network bandwidth usage."*). Each
Disconnect = one successful state-part transfer completing. Repeated
Disconnects = repeated successful transfers, which is the *desired*
path.

**Verdict**

End-to-end fix works in TDX. Specifically validated:

1. **Launcher reads `tier3_public_addr`** from the TOML and propagates
   it into the neard config inside the CVM. Verified: the
   `near_tier3_public_addr` metric shows the exact configured value
   (`51.68.219.13:24567`), not the auto-discovered outbound IP that the
   unfixed case would produce.
2. **`external_storage_fallback_threshold = 1000` was applied.**
   Verified: DSS attempts happen at all — with the previous hardcoded
   `0`, the node would have gone straight to bucket and we'd see no
   `near_state_sync_download_result{source="network"}` entries.
3. **Real testnet peers reach the CVM through the full network stack.**
   Verified: 13–29 Tier3 inbound connections at peak, 1019 successful
   part downloads, ~96% success rate. State sync of shard 5 completed
   entirely via DSS in ~55 min, with zero bucket fallbacks. Node is now
   caught up at testnet tip and processing recent blocks normally.

The TDX / dstack / QEMU / docker networking layers do **not** introduce
additional failure modes beyond the host-level asymmetric-IP issue we
already identified — once `tier3_public_addr` is set, the fix is the
same on bare metal and in TDX.

### Test 6 — Option 3b validated in TDX, isolated from Option 0 (run 2026-05-07 on Alice)

Companion to Test 5: deliberately deploy *without* `tier3_public_addr`
and rely **only** on a host-level iptables SNAT rule (Option 3b in this
doc). Goal: prove the host-only fix works without any node config or
code change.

Setup:
- Same custom mpc-node image as Test 5 (still PR #3145's image, but the
  PR's fields are *unset* in the launcher TOML — so PR #3145 is a no-op
  for this run).
- `single-node-testnet.sh` invoked with `TIER3_PUBLIC_ADDR=""` (the
  script omits the line from the rendered TOML when empty).
- Single iptables rule on the host:
  ```bash
  sudo iptables -t nat -I POSTROUTING 1 \
    -p tcp --dport 24567 -o ens49f0np0 \
    -j SNAT --to-source 51.68.219.13
  ```
  Matched by destination port `:24567` because dstack uses QEMU
  user-mode slirp (no host-visible CVM bridge IP to match on, the
  recipe in [Concrete recipe for Option 3b](#concrete-recipe-for-option-3b-on-boballe-multi-ip-ovh-host)
  notes this).
- CVM was restarted *after* the SNAT rule was installed (initial deploy
  raced — neard's first peer connections established before the rule
  hit POSTROUTING, so conntrack pinned them with no SNAT and
  auto-discovery latched onto the wrong IP). Restart resolved this.

Final metrics after 32 min uptime:

```
near_tier3_public_addr{addr="51.68.219.13:24567"} 1   ← auto-discovered, no config field set ✅
near_block_height_head 249137957                       ← jumped to testnet tip ✅
near_sync_status 7                                     ← past state sync, in block sync now ✅

near_state_sync_download_result{result="success",  type="header"} 1
near_state_sync_download_result{result="success",  type="part"}   1019   ← full state sync ✅
near_state_sync_download_result{result="timeout",  type="part"}   29
near_state_sync_download_result{result="sender_dropped",..."part"} 20
near_state_sync_download_result{result="route_not_found",..."part"} 16

near_peer_connections{peer_type="Outbound",tier="T2"} 18
near_peer_connections{peer_type="Inbound",tier="T2"}  (absent — 0)   ← still ❌
```

State sync of shard 5 completed in ~32 min (faster than Test 5's 55 min).
SNAT rule packet counter climbed past 130, confirming the rule was
matching outbound peer-port-24567 traffic.

**Verdict:** Option 3b correctly fixes the source-IP discovery — once
in place, `near_tier3_public_addr` auto-discovers `51.68.219.13:24567`
and DSS proceeds normally.

**Important caveat about "no code changes":** Test 6 ran *with* PR #3145's
binary AND with `external_storage_fallback_threshold = 1000` set in the
launcher TOML. Without PR #3145, `patch_near_config` hardcodes the
threshold to `0` (bucket-only) — DSS is never *attempted* in the first
place, so Option 3b's source-IP correction has nothing to act on. So
Option 3b is **not** a code-free alternative to Option 0; it's an
alternative to Option 0's `tier3_public_addr` field while still relying
on Option 0's `external_storage_fallback_threshold` field. The smallest
"truly code-free" Option 3b would require us to also remove the
hardcoded `= 0` line in `patch_near_config` (a one-line code change,
smaller than the rest of PR #3145).

The SNAT rule must be in place *before* neard starts making peer
connections — otherwise conntrack pins the pre-SNAT mapping and
auto-discovery ends up wrong (mitigated by restart-after-rule).

### Test 6 takeaway: Tier2 inbound recovery is unrelated to either fix

A surprising finding from comparing Test 5 and Test 6 directly:

|  | Option 0 (Test 5) | Option 3b (Test 6) |
|---|---|---|
| `near_tier3_public_addr` correct | ✅ via config | ✅ via SNAT auto-discovery |
| State sync completed | ✅ in ~55 min | ✅ in ~32 min |
| Successful state parts | 1019 | 1019 (same) |
| Success rate | 96.3% | ~94% |
| **`peer_connections{Inbound,T2}`** | **0 (after 1.5+ days)** | **0 (after 32 min)** |
| Requires PR #3145 | yes (both new fields) | yes (`external_storage_fallback_threshold` only) |
| Hardcoded IP in node config | yes (`tier3_public_addr`) | no |
| Host root required | no | yes (iptables) |
| Persistence | trivial (file) | systemd / iptables-persistent |

**Both options leave Tier2 inbound at zero**, despite Option 3b correcting
the source IP that peers observe (so gossiped `PeerInfo` is correct from
the moment of restart). This contradicts the working hypothesis that
fixing the gossiped address would let other peers dial us inbound.

What this means:
- The "missing Tier2 inbound peers" symptom is **not** primarily caused
  by the wrong gossiped `PeerInfo`. Peers don't actively dial random
  gossiped addresses, so even a correct address may not produce inbound
  connections quickly.
- It's likely a function of network demand / convergence time, not of
  the fix mechanism. Bob's mainnet GCP node has 9 inbound T2 because
  it's been running long enough to be in many peers' active connection
  set. Fresh nodes (us, Bob's TEE) won't catch up in minutes.
- For our deployment, this means **Option 3b's purported "bonus benefit
  of also fixing Tier2 inbound" is not real in practice** — at least not
  on the timescale we tested. Both fixes deliver DSS equally well.

## Scope of impact

The bug only affects deployments where:

- the host has **multiple public IPs on one NIC** (or asymmetric SNAT/DNAT
  configurations where outbound source IP differs from inbound destination
  IP), **and**
- `:24567` is bound to a specific IP that's **not** the one Linux picks
  for outbound traffic.

Concretely:

| Deployment | Topology | Affected? |
|---|---|---|
| GCP single-VM (mainnet today) | One ext IP via 1:1 NAT | No |
| AWS single-VM | One ext IP via Elastic IP / public IP | No |
| Plain VPS with one public IP | Single IP per NIC | No |
| OVH bare-metal with additional IPs (Bob, Alice) | Many IPs on one NIC | **Yes** |
| Hetzner / similar with floating IPs | Depends on routing config | Likely yes if floating IP is the bound one but not the default route source |
| Container behind 1:1 host NAT | Same as host | Same as host |

So the production fleet today is essentially: mainnet GCP (fine) + testnet
TEE on Bob (broken) + future TEE deployments depending on the host they
land on.

## Mechanism — exactly why auto-discovery picks the wrong IP

Four-step chain in `chain/network/src/peer/peer_actor.rs`:

1. neard makes outbound connection to a peer. Linux picks the source IP
   from the matching route (default route → dynamic IP `57.129.140.254` /
   `91.134.92.20`).
2. The peer observes the connection from `<outbound_ip>:<ephemeral>` and
   reads `sender_listen_port = 24567` from neard's handshake.
3. The peer constructs
   `PeerInfo { addr: SocketAddr::new(observed_source_ip, sender_listen_port) }`
   = `<outbound_ip>:24567`. It includes that in `PeersResponse` replies and
   gossips it to other peers.
4. Our neard reads `PeersResponse`, finds its own ID inside `direct_peers`,
   and records `my_public_addr = <outbound_ip>:24567`. That value flows
   into the `near_tier3_public_addr` metric and into every Tier3 state
   request we send.

The assumption: *"the IP we egress from is the IP others should connect
to"* holds on a single-IP host. It breaks when the outbound source ≠
inbound bind IP — exactly our case. There's no consensus check, no
loopback verification — just trust what the first peer reports.

## Why bucket sync had been masking this

`deployment/start.sh:46` for any non-localnet env:

```python
config['state_sync']['sync']['ExternalStorage']['external_storage_fallback_threshold'] = 0
```

`= 0` means "never use P2P, always use external bucket." So **no MPC node
in production has ever exercised DSS** — the bug existed all along, latent.
fast-state-parts being decommissioned forced operators to consider DSS,
and that's when the bug surfaced.

## Recommended fix

For the existing testnet TEE node and for the MPC deployment in general:

1. **Set `tier3_public_addr` per-node** in `config.json`. Inject it via
   `start.sh` (which already writes the neard config), or thread it through
   the launcher TOML's `near_init` section. Value: the static IP that the
   port-forward / `network.addr` uses, with port `24567`.

2. **Stop hardcoding `external_storage_fallback_threshold = 0`** in
   `start.sh` once (1) is in place. Let DSS actually run as nearcore
   intends.

3. *(Optional)* For multi-node-on-same-host setups, also add per-process
   source-IP routing (UID-based `ip rule` for native processes, per-CVM
   SNAT for containerized) so that gossiped `PeerInfo` is also correct
   and inbound Tier2 peers can find each node. Without this, `tier3_public_addr`
   alone is enough for DSS but each node will still have zero Tier2 inbound
   peers from the wider network. For TEE that's likely acceptable; for
   non-TEE deployments it depends on operational expectations.

For Bob specifically: apply (1) and (2) to the testnet TEE node via the
dstack-vmm "Update VM Config" flow + Shutdown → Start (per the on-call
runbook in `mpc-private` PR #304). The deployed `user-config.toml` is the
right place to inject the field; `start.sh` then writes it into
`config.json`.

## Network-level options for multi-node hosts

`tier3_public_addr` fixes Tier3 (state sync) — sufficient for unblocking #1734.
But it does **not** fix the gossip path: peers still learn our address as
`<outbound_ip>:24567` via `PeerInfo` gossip, and `peer_type="Inbound",tier="T2"`
stays at zero. If a deployment cares about regular Tier2 inbound peers
landing (e.g., for general P2P network health, faster propagation, future
features that depend on incoming Tier2), the outbound *source IP* itself
needs to match the bound IP.

Six options, ordered by how much we have to touch:

### Option 0 — `tier3_public_addr` only (the validated fix)

Add `network.experimental.tier3_public_addr = "<bound_ip>:24567"` to each
node's `config.json`. Forces neard to advertise the right address, ignoring
auto-discovery.

- **Type:** node config change. **No code changes** to nearcore or
  mpc-node. Field already exists in `config.json` schema (since nearcore
  ≥ 2.10).
- **Pros:**
  - One-line config change per node.
  - No host-level networking touched — works alongside docker, CVM, dstack.
  - Survives reboots and DHCP renewals trivially (just file content).
  - Independent per-node — multi-node-on-one-host friendly.
- **Cons:**
  - Fixes Tier3 only. Tier2 inbound peers (gossiped `PeerInfo` path) stay
    broken; node remains "outbound-only" on T2.
  - IP is hardcoded — if the bound IP ever changes, the config needs to
    be updated.
- **Performance:** none.

### Option 1 — bind `network.addr = "0.0.0.0:24567"`

Make `:24567` listen on every IP on the host. Auto-discovery's answer
(whatever outbound IP it picks up) becomes valid because there's a listener
on that IP too.

- **Type:** node config change. **No code changes.**
- **Pros:**
  - Fixes both DSS *and* the Tier2 inbound-peers issue with one line.
  - No host-level networking changes.
  - Cheapest setup.
- **Cons:**
  - **Single-node only** — can't run two nodes on the same host (port
    conflict on `:24567`).
  - All host IPs become potential entry points to the node, which may
    surprise security review or audit (vs. binding to one specific IP).
- **Performance:** none.

### Option 2 — host-wide default-route source override

Change which IP outbound traffic exits as, host-wide:

```bash
sudo ip route replace default via 100.64.0.1 dev ens49f0np0 src 51.68.219.13
```

After this, `ip route get 8.8.8.8` reports `src 51.68.219.13`, and
auto-discovery picks the right address for *every* process on the host.

- **Type:** host network config. **No code changes.**
- **Pros:**
  - Fixes both DSS and the gossip / Tier2 inbound-peers issue.
  - Single command, applies to anything on the host (not just neard).
- **Cons:**
  - Affects **all outbound traffic** on the host (Docker, SSH, monitoring,
    package mirrors). Anything elsewhere whitelisted on the previous
    outbound IP breaks.
  - DHCP / `networkd` may re-install its own default route on lease
    renewal — needs a persistent post-up hook (systemd unit,
    `/etc/networkd-dispatcher`, etc.).
  - Doesn't scale to multi-node — only one default-route source can
    exist on a host.
- **Performance:** none.

### Option 3 — per-process / per-CVM source IP

The right answer when you want different nodes on one host to advertise
different IPs.

**3a. Native processes — UID-based policy routing.**
Run each node as its own user, then add per-UID routing tables:

```bash
# Run each node as a separate UNIX user
sudo useradd -m mpc1   # UID 1001
sudo useradd -m mpc2   # UID 1002

# Per-node routing tables
sudo ip route add default via 100.64.0.1 dev ens49f0np0 src 51.68.219.13 table 201
sudo ip route add default via 100.64.0.1 dev ens49f0np0 src 51.68.219.14 table 202

# Policy rules: bind each user to its table
sudo ip rule add uidrange 1001-1001 lookup 201
sudo ip rule add uidrange 1002-1002 lookup 202
```

Now `mpc1`'s outbound exits as `51.68.219.13`, `mpc2`'s as `51.68.219.14`.
Auto-discovery records the right IP for each, gossip is correct,
inbound Tier2 peers can connect.

- **Type:** host network config + run-as-user. **No code changes.**
- **Applies to:** native (non-CVM) deployments only.
  **Does NOT apply to TEE/CVM deployments** — every dstack CVM on a host
  is launched by the same `dstack-vmm` daemon under one UNIX user, so
  a `uidrange` rule cannot distinguish CVMs from each other.
- **Pros:**
  - Per-node, scales to as many nodes as you have static IPs.
  - Doesn't affect rest of host's outbound traffic.
  - Fixes both DSS and Tier2 inbound peers.
- **Cons:**
  - Tied to UID — if a node is ever restarted under a different user,
    the rule silently goes stale.
  - Needs persistence across reboots (systemd `ip-rule` unit or
    `/etc/networkd-dispatcher` script).
  - Requires that each node actually run as its own UNIX user — adds
    a small operational requirement.
  - Doesn't fit TEE/CVM (see "Applies to" above).
- **Performance:** kernel does one extra rule lookup in the routing
  decision per outgoing packet. Negligible (sub-microsecond).

**3b. Containers / CVMs — per-CVM SNAT on the host.**
Each CVM has its own private IP on a docker / qemu bridge. SNAT on the
host's POSTROUTING chain rewrites outbound source IP per CVM, identifying
the CVM by its bridge-side address:

```bash
sudo iptables -t nat -A POSTROUTING -s <cvm1_bridge_ip>/32 \
  -o ens49f0np0 -j SNAT --to-source 51.68.219.13
sudo iptables -t nat -A POSTROUTING -s <cvm2_bridge_ip>/32 \
  -o ens49f0np0 -j SNAT --to-source 51.68.219.14
```

Same correctness as 3a, but matched at the host's NAT layer on the CVM's
bridge IP rather than at policy-routing time on the UID. CVMs themselves
don't need any networking changes.

- **Type:** host iptables config. **No code changes** to neard, mpc-node,
  or the launcher. CVMs unchanged.
- **Applies to:** TEE/CVM deployments (the case 3a does *not* cover) —
  works identically for plain Docker containers.
- **Pros:**
  - Native to container/CVM workflows — applies cleanly to dstack
    deployments.
  - Each CVM gets its own outbound IP without any in-CVM config.
  - Doesn't affect host's other traffic.
  - Fixes both DSS and Tier2 inbound peers.
- **Cons:**
  - iptables rules need persistence (`iptables-persistent`, systemd unit,
    or whatever the host uses).
  - Tied to the CVM bridge IPs being stable — which they generally are,
    but a re-deploy that changes the bridge layout breaks the rule.
  - SNAT relies on connection tracking — adds a small per-flow overhead.
- **Performance:** SNAT adds conntrack entry + rewrite per packet.
  For neard's traffic profile (a few hundred TCP connections, modest
  PPS), CPU overhead is in the noise. Becomes meaningful only at much
  higher throughput than neard generates.

### Concrete recipe for Option 3b on Bob/Alice (multi-IP OVH host)

Practical playbook for the only host topology where #1734 actually bites
in our deployment (multiple public IPs on one NIC, default route picks
the dynamic one). Same template applies to any analogous bare-metal host.

**1. Identify each CVM's bridge IP.** The dstack/QEMU launcher attaches
each CVM to a bridge interface (often `virbr0` for libvirt, or a
docker-managed bridge). Each CVM gets a private IP on that bridge:

```bash
# Find the bridge the CVMs are attached to
ip -4 addr show | grep -E "virbr|br-" | head -5

# Inspect each running CVM's bridge IP — name varies by CVM tooling
sudo ip -4 neigh show dev virbr0 2>/dev/null
# or check the QEMU hostfwd / dnsmasq leases:
sudo cat /var/lib/libvirt/dnsmasq/virbr0.status 2>/dev/null
# or for docker-driven bridges:
docker inspect <launcher-container> --format='{{.NetworkSettings.IPAddress}}'
```

**2. Pick the static public IP this CVM should be observed at.** Must be
one already bound to the host's NIC (`ip -4 addr show ens49f0np0`) and
configured as the `EXTERNAL_*` host of the deploy script's port-forward
mappings. For the testnet TEE node on Bob: `46.105.87.136`.

**3. Install the SNAT rule:**

```bash
# Replace <cvm_bridge_ip> with the CVM's private bridge IP from step 1,
# and ens49f0np0 with the host's outbound NIC name.
sudo iptables -t nat -A POSTROUTING \
  -s <cvm_bridge_ip>/32 \
  -o ens49f0np0 \
  -j SNAT --to-source 46.105.87.136
```

**4. Persist across reboots.** The simplest:

```bash
sudo apt install iptables-persistent     # if not already
sudo netfilter-persistent save
```

Or as a systemd unit / `if-up.d` hook keyed off the bridge interface
coming up — cleaner if you want the rule re-applied automatically when
the bridge is recreated by a re-deploy.

**5. Verify the fix landed.** Without restarting the CVM:

```bash
# (a) Source IP that outbound traffic now egresses with — should match
# the SNAT --to-source value (46.105.87.136), not the dynamic IP.
# Run from inside the CVM (or check via tcpdump on the host's NIC):
sudo tcpdump -n -i ens49f0np0 'tcp and dst port 24567' -c 3

# (b) After restarting neard so auto-discovery re-runs, the metric
# should show the corrected address:
curl -s http://<host>:8080/metrics | grep near_tier3_public_addr
# Expected: addr="46.105.87.136:24567" (NOT the previous "91.134.92.20:...")

# (c) Inbound Tier2 peer count should climb from 0 over the next few minutes
# as the network re-discovers our correct PeerInfo via gossip.
curl -s http://<host>:8080/metrics | grep 'near_peer_connections{peer_type="Inbound"'
```

If (a) still shows the old IP, the rule isn't matching — usually means
the wrong bridge IP in step 1, or another POSTROUTING rule is matching
first (`sudo iptables -t nat -L POSTROUTING -n -v --line-numbers` shows
ordering and hit counts).

### Option 4 — neard binds outbound source IP (upstream code change)

Most "correct" solution architecturally: have neard bind its outbound
TCP connections to a specific local source IP, instead of letting the
kernel pick from the default route. Auto-discovery would then record
the right IP without any host or environment hacks.

- **Type:** **upstream nearcore code change.** Would need a new
  `network.outbound_source_addr` (or similar) config field, plus a
  `bind()` call before each `connect()` in `chain/network/src/peer/peer_actor.rs`
  (or wherever the TCP connect happens).
- **Pros:**
  - Cleanest architectural fix — solves the asymmetric-IP problem at
    the root.
  - Pure config from operators' perspective (no host networking
    knowledge needed).
  - Per-node naturally — multi-node-friendly.
  - Fixes both DSS and Tier2 inbound peers (because peers would observe
    the correct source IP).
- **Cons:**
  - Requires upstream PR to nearcore + waiting for a release.
  - Doesn't help us today; we'd still need Option 0 in the meantime.
  - Possible interaction with IPv4/IPv6 dual-stack — implementation
    needs to handle that explicitly.
- **Performance:** none.

### Option 5 — dedicated network namespace per node

Run each node inside its own Linux network namespace with only the
intended IP visible / routable. Outbound from inside the namespace can
only egress as that IP. Strongest isolation.

- **Type:** host networking + process isolation. **No code changes.**
- **Pros:**
  - Strongest isolation — node literally cannot see other IPs on the
    host.
  - Fixes both DSS and Tier2 inbound peers.
  - Per-node, scales arbitrarily.
- **Cons:**
  - Heavyweight setup — netns + veth + routing per node.
  - Affects every other network-touching detail (DNS, monitoring, debug
    access — all need to be re-wired into the namespace).
  - Operationally complex; harder to debug than UID routing or SNAT.
- **Performance:** veth pair adds one extra hop per packet (memory copy
  + interface dispatch). Tiny — comparable to docker bridge networking.

### Comparison table

> **Note about "Available today":** stock MPC `main` hardcodes
> `external_storage_fallback_threshold = 0` in `patch_near_config`
> (`crates/node/src/config/start.rs`), which forces bucket-only and
> means **DSS is never attempted at all**. So none of the options below
> actually enable DSS on stock main — they all require *some* code
> change to lift that hardcoded threshold. PR #3145 adds it as a
> launcher TOML field; the smallest possible fix is to just remove the
> hardcoded line. The "Available today" column reflects what's needed
> *beyond* that.

| # | Solution | Type | Needs (besides DSS-enable) | Fixes DSS (Tier3) | Fixes Tier2 inbound | Multi-node on one host | Persistence | Perf impact |
|---|---|---|---|---|---|---|---|---|
| **0** | **`tier3_public_addr` per-node** | Node config | PR #3145 (the field itself) | ✅ | ❌ (empirical, Test 5) | ✅ | trivial (file) | none |
| 1 | `network.addr = "0.0.0.0:24567"` | Node config | nothing extra | ✅ | likely ✅ (untested) | ❌ (port conflict) | trivial (file) | none |
| 2 | Host-wide default-route source | Host network config | nothing extra | ✅ | likely ✅ (untested) | ❌ | needs systemd hook | none |
| 3a | UID-based policy routing | Host network + run-as-user | nothing extra | ✅ | likely ✅ (untested) | ✅ | needs systemd hook | negligible |
| **3b** | **Per-CVM SNAT on host** | Host iptables | nothing extra | ✅ (Test 6) | ❌ (empirical, Test 6) | ✅ | needs `iptables-persistent` or systemd | low (conntrack + per-packet rewrite) |
| 4 | neard binds outbound source IP | Upstream nearcore code change | upstream PR + release | ✅ | likely ✅ (untested) | ✅ | trivial (file, once shipped) | none |
| 5 | Network namespace per node | Host networking + process isolation | nothing extra | ✅ | likely ✅ (untested) | ✅ | needs systemd hook | low (veth pair per packet) |

### Picking between them

| Scenario | Use |
|---|---|
| **Today, immediate DSS fix on Bob** | **Option 0** (`tier3_public_addr` per-node) — unblocks DSS without touching the host |
| One node per host, simplest setup | Option 1 (`0.0.0.0` bind) — also fixes Tier2 inbound |
| One node per host, can't bind on `0.0.0.0` for some reason | Option 2 (default-route override) |
| Multiple **CVMs/TEE** per host (Bob's case) | **Option 3b** (per-CVM SNAT) — plus Option 0 as defense in depth |
| Multiple **native** nodes per host (no TEE) | Option 3a (UID routing) — plus Option 0 as defense in depth |
| Long-term, future MPC release | Option 4 (upstream nearcore feature) |
| Maximum isolation between nodes | Option 5 (netns) — plus Option 0 |

> **Note for TEE deployments**: Option 3a (UID-based) does **not** apply —
> all CVMs on a host run under the same `dstack-vmm` UID, so per-UID rules
> can't distinguish them. The TEE-correct host-level fix is **Option 3b**
> (per-CVM SNAT keyed off bridge IP), or — if a single CVM per host is
> acceptable — Option 1 / 2.

**Concrete recommendation for Bob:**

Both Option 0 and Option 3b are now empirically validated (Tests 5 and 6
respectively). They deliver the same DSS correctness; **neither
recovers Tier2 inbound** in the test windows. So the choice between them
is operational, not functional.

1. **Recommended: Option 0** (`tier3_public_addr` in launcher TOML, via
   PR #3145).
   - Operationally simpler — one TOML field, no host root, no iptables
     persistence to maintain.
   - The fix lives with the node config, so it travels with the
     deployment automatically. No host-side state to forget on a
     migration.
   - Validated end-to-end on TDX (Test 5).
2. **Alternative: Option 3b** (per-host iptables SNAT).
   - Faster state sync in our test (~32 min vs ~55 min for Option 0),
     possibly because the source IP is correct from the moment of the
     first peer connection rather than only on the request payload.
   - No node code/config changes — useful if you can't redeploy nodes
     but can change the host.
   - Cost: requires root on the host, an iptables rule that needs
     persistence (systemd / `iptables-persistent`), and a SNAT rule
     installed *before* neard starts (otherwise conntrack pins the
     pre-SNAT mapping and the fix is wasted).
3. **Eventually:** if upstream Option 4 lands in a future nearcore
   release, we can drop both Option 0 and Option 3b in favor of native
   outbound source-IP binding.

We initially expected Option 3b's bonus over Option 0 to be "also
recovers Tier2 inbound peers" — that turned out **not** to materialize
empirically (see Test 6 takeaway above). So there's no functional
reason to prefer 3b over 0; the choice is purely operational.

## Important nuances

- **Binding `network.addr = "0.0.0.0:24567"`** would also fix DSS *and*
  the missing-inbound-peers symptom, by making `:24567` listen on every
  IP including the outbound one. **But** it precludes running multiple
  nodes on one host (port conflict). For deployments where that matters
  (e.g., MPC localnet/testing, or future multi-tenant hosts), `0.0.0.0`
  bind isn't an option — `tier3_public_addr` per-node is the
  application-level fix that survives.

- **The fix is forward-compatible with future nearcore changes.** The
  `tier3_public_addr` field is supported by all current nearcore versions
  (2.11.x and beyond) and is the path nearcore's own error message
  recommends.

- **Persistence:** `tier3_public_addr` lives in `config.json`, survives
  reboots and DHCP renewals trivially. Network-level fixes (policy
  routing, SNAT) need systemd / network-config persistence work.

## Does the MPC node actually need inbound Tier2?

Strictly: **no.** The MPC node functions correctly outbound-only.

- The MPC signing protocol uses its own `mpc-tls` mesh on a different
  port — *not* neard's Tier2. neard's network layer is purely for chain
  consumption (indexer follows blocks, transactions get submitted, state
  reads).
- A Tier2 TCP socket is bidirectional once established — "outbound" only
  describes who initiated. Routed messages can flow *to* us through our
  outbound connections, which is why Bob's TEE node has still served 240
  state-sync requests as a snapshot host despite 0 inbound.

What outbound-only does cost:

- **Less peer redundancy.** If our outbound peers go offline together, we
  reconnect from scratch.
- **Bad network citizenship.** We consume bandwidth (block propagation,
  routed messages) without offering ourselves as an entry point.
- **Slightly slower block propagation** in pathological peer sets — fewer
  redundant gossip paths to us.
- **Less useful as a relay** for other nodes' routed messages (peers don't
  know about us, so our `RoutingTableActor` rarely shows up in their
  paths).
- *Not relevant for us:* validator Tier1 bootstrap depends on Tier2 peer
  discovery. We're not validators.

So fixing inbound Tier2 is **"should-do, not must-do."** Same root cause
as DSS, no extra structural work if Option 3b is adopted on the host, but
not blocking #1734.

## Open questions / follow-ups

- Should `start.sh` derive `tier3_public_addr` automatically (e.g., from
  `EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC` env var stripped of `0.0.0.0`),
  or should the launcher TOML's `near_init` section grow an explicit
  field? Both work; explicit field is more discoverable.

- Once `external_storage_fallback_threshold = 0` is removed from
  `start.sh`, decide on a non-zero default — `1000`, "always try P2P
  first," or remove the bucket entirely. Coordinate with the nearcore
  team on the deprecation timeline for `state-parts`.

## Key code references

- `chain/network/src/tcp.rs` — `Tier` enum (T1/T2/T3) docs.
- `chain/client/src/sync/state/network.rs` — Tier2 state request flow,
  `MyPublicAddrNotKnown` short-circuit.
- `chain/network/src/peer_manager/peer_manager_actor.rs` — where
  `MyPublicAddrNotKnown` is returned (state header + part request handlers).
- `chain/network/src/peer/peer_actor.rs` — `my_public_addr` auto-discovery
  from `PeersResponse`; handshake → `PeerInfo { addr: source_ip + sender_listen_port }`.
- `chain/network/src/peer_manager/network_state/mod.rs` —
  `my_public_addr: Arc::new(RwLock::new(config.tier3_public_addr))` (config
  pre-seeds it).
- `chain/network/src/config_json.rs` — `tier3_public_addr: Option<SocketAddr>`
  (format `"IP:port"`).
- `chain/client/src/sync/state/downloader.rs` — the explicit "Tier3
  connectivity issue" log message.
- `deployment/start.sh:46` — hardcodes `external_storage_fallback_threshold = 0`
  for non-localnet, disabling DSS in practice today.
