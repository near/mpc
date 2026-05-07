# Fixing DSS state-sync timeouts on multi-IP hosts

Operator guide for the bug tracked in
[#1734](https://github.com/near/mpc/issues/1734). For the underlying
root-cause analysis, see
[`docs/analysis/issue-1734-dss.md`](./analysis/issue-1734-dss.md).

## When you need this

You are affected if **all** of these are true:

1. Your MPC node runs on a host with **multiple public IPs on one NIC**
   (typical of OVH / Hetzner bare-metal — `ip -4 addr show <nic>` shows
   several `inet` lines).
2. `:24567` is bound to **one specific** static IP on the host (e.g. via
   `EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC=51.68.219.13:24567`), not
   `0.0.0.0`.
3. Outbound traffic egresses with a **different** IP from that bound
   one. Check:
   ```bash
   ip route get 8.8.8.8
   # 8.8.8.8 via 100.64.0.1 dev <nic> src <outbound_ip>
   ```
   If `<outbound_ip>` differs from your bound `:24567` IP — you're
   affected.

You are **not** affected on a single-IP host (most cloud VMs — GCP, AWS
single-VM, etc.). The bug only manifests when outbound source IP differs
from inbound bind IP.

## Symptoms

DSS state sync times out continuously. Visible in metrics
(`http://<node>:<metrics-port>/metrics`):

- `near_tier3_public_addr{addr="..."}` reports the **outbound** IP, not
  the bound IP — that's the canary.
- `near_state_sync_download_result{result="timeout",source="network"}`
  climbs while `result="success"` stays at 0.
- nearcore log warns:
  > "state sync header retrieval is failing repeatedly. This may
  > indicate a Tier3 connectivity issue - peers cannot connect back to
  > deliver state data. Check: ... if behind NAT, set
  > `network.experimental.tier3_public_addr` in `config.json`."

## Quick diagnostic

```bash
# 1. What does the node advertise?
curl -s http://<your-node>:<metrics-port>/metrics | grep near_tier3_public_addr

# 2. What IP does the host outbound exit as?
ip route get 8.8.8.8 | awk '/src/ {print $7}'

# 3. What IP is :24567 bound on (host)?
sudo ss -ltn | grep ':24567'
```

If (1) matches (2) but **not** (3) → you have this bug.

---

## Option A (recommended): set `tier3_public_addr` in the launcher TOML

Lives in node config; no host root or iptables work; survives reboots
trivially. **This is what we ship in PR #3145.**

In the launcher's user-config TOML, add to the `[mpc_node_config.near_init]`
section:

```toml
[mpc_node_config.near_init]
chain_id = "testnet"            # existing
boot_nodes = "..."              # existing
download_genesis = true         # existing
download_config = "rpc"         # existing

# NEW — set to the same IP:port your dstack port-forward uses for :24567
tier3_public_addr = "51.68.219.13:24567"

# NEW (optional) — enable DSS-first behavior. 0 (current default) =
# bucket-only and DSS never runs. 1000 = try DSS up to 1000 times before
# falling back to bucket as a safety net. Required if you want DSS to
# actually be exercised once bucket sync is decommissioned.
external_storage_fallback_threshold = 1000
```

For the dstack TEE deployment specifically: edit the user-config file
through the dstack-vmm "Update VM Config" modal (per
[`mpc-private` PR #304's runbook](https://github.com/near/mpc-private/pull/304)),
then **Shutdown → Start** the CVM to apply.

### Verify

After restart, hit the metrics endpoint. Expect:

```bash
curl -s http://<node>:<metrics-port>/metrics | grep near_tier3_public_addr
# near_tier3_public_addr{addr="51.68.219.13:24567"} 1
```

If the address matches what you configured (and **not** the dynamic
outbound IP), the fix is live.

DSS attempts should start succeeding within a minute:

```bash
curl -s http://<node>:<metrics-port>/metrics | grep near_state_sync_download_result
# expect near_state_sync_download_result{result="success",source="network",type="part"} climbing
```

---

## Option B (alternative): host-level iptables SNAT

For hosts where you can't easily change the launcher TOML, or you'd
rather fix it once at the host level. Equivalent correctness; somewhat
harder to operate.

```bash
# Replace 51.68.219.13 with your bound IP and ens49f0np0 with your NIC.
sudo iptables -t nat -I POSTROUTING 1 \
  -p tcp --dport 24567 -o ens49f0np0 \
  -j SNAT --to-source 51.68.219.13
```

Persist across reboots:

```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

Or via a systemd unit / `if-up.d` hook keyed off the bridge interface
coming up.

### Critical: timing matters

The SNAT rule must be in place **before** neard starts making peer
connections. Otherwise conntrack pins the existing connections with no
SNAT, neard's auto-discovery latches onto the wrong IP, and the rule
applies only to *new* connections. The fix won't take effect until you
restart the node.

For a freshly-deployed node, install the rule, then deploy.
For an already-running node, install the rule, then restart neard (or
the whole CVM).

### Verify

Same metric check as Option A:

```bash
curl -s http://<node>:<metrics-port>/metrics | grep near_tier3_public_addr
# near_tier3_public_addr{addr="51.68.219.13:24567"} 1   ← right IP via auto-discovery
```

Also confirm the SNAT rule is matching packets:

```bash
sudo iptables -t nat -L POSTROUTING -n -v --line-numbers | head -3
#       pkts  bytes  target  ...
# 1     <N>   <B>    SNAT    ... tcp dpt:24567 to:51.68.219.13
```

The `pkts` column should be non-zero and climbing — those are your
node's outbound connections to peers being SNAT'd.

---

## Picking between the two options

| | Option A (`tier3_public_addr`) | Option B (iptables SNAT) |
|---|---|---|
| Lives in | node config (TOML) | host firewall |
| Requires root on host | no | yes |
| Persistence | trivial (file) | needs systemd / `iptables-persistent` |
| Survives node redeploy | yes | yes |
| Survives host migration | depends on whether new host has the same IP setup | no — host config doesn't travel |
| Minimum nearcore version | 2.10+ | any |
| Restart required to apply | yes (once) | yes (once, *after* rule install) |

**Recommendation: Option A**, unless you specifically need a host-level
fix (e.g., you can't redeploy the node, or you're standardizing on
host-level network policy across many nodes).

Both options are validated end-to-end on a TDX CVM (Tests 5 and 6 in
the [analysis doc](./analysis/issue-1734-dss.md)). They deliver the same
DSS correctness; neither recovers `peer_connections{Inbound,T2}` in
test windows up to 1.5 days, so don't pick Option B expecting that as a
bonus.

## Common pitfalls

- **The bound IP changed.** If your dstack port-forward target changes
  (e.g., you migrate from `51.68.219.13` to `51.68.219.14`), update
  `tier3_public_addr` (Option A) or the SNAT `--to-source` (Option B)
  to match. They must agree with the IP that's actually port-forwarded.
- **`external_storage_fallback_threshold = 0`** (the default in
  `start.sh` historically) means **DSS never runs**, regardless of
  whether `tier3_public_addr` is set. If you want to actually exercise
  DSS, set the threshold to a non-zero value (1000 is a safe
  DSS-first-with-bucket-fallback choice).
- **Forgetting to restart neard** after a config change. Both options
  only take effect after a fresh process startup so peer-connection
  state and `my_public_addr` are re-derived.
- **iptables rule installed too late** (Option B). If neard already
  established connections before the rule was installed, conntrack
  pinned them without SNAT — those connections are useless for the
  fix. Restart neard to drop the conntrack entries and force fresh
  connections.

## What this fix does NOT change

- **Existing peer connections aren't retroactively SNAT'd / re-discovered.**
  Both fixes only take effect on neard restarts.
- **Tier2 inbound peers** (`peer_connections{Inbound,T2}`) — neither
  fix produces these in our test windows. The MPC node functions fine
  outbound-only; this is a separate hygiene issue.
- **Bucket sync configuration** — both fixes are about DSS only. If
  you're still relying on the external bucket for state sync, leave the
  threshold at 0 and the bucket settings as-is; this fix doesn't change
  bucket behavior.
