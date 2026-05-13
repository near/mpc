# Running multiple MPC nodes on one host

Companion to the [TDX operator guide](./running-an-mpc-node-in-tdx-external-guide.md).
Covers the case where you want to run **two MPC nodes on the same
bare-metal TDX host** — typically a mainnet node and a testnet node
sharing one machine.

## When you'd use this

Two reasons operators consider this:

- **Hardware cost.** Renting a bare-metal TDX server is materially
  more expensive than a typical cloud VM. Running both mainnet and
  testnet on one server avoids paying for a second TDX host.
- **Operational complexity.** One TDX setup to provision, harden,
  patch, and monitor instead of two — same upgrade cadence, half the
  host-side overhead.

If you're new to running a TDX MPC node, start with the
[TDX operator guide](./running-an-mpc-node-in-tdx-external-guide.md)
and a single node. Come back here once you have one node working.

## Prerequisites

In addition to the standard [hardware requirements](./running-an-mpc-node-in-tdx-external-guide.md#hardware-requirements):

- **At least two routable public IPs** on the host's NIC, one per
  node. Same NIC is fine; what matters is that each CVM can be
  port-forwarded to a distinct external IP.
- **2× the single-node hardware** ([single-node minimums](./running-an-mpc-node-in-tdx-external-guide.md#hardware-requirements)
  apply per CVM): ≥ 128 GB memory, ≥ 16 cores, ≥ 1 TB SSD/NVMe disk.
- **Firewall opened on both IPs** for the [required ports](./running-an-mpc-node-in-tdx-external-guide.md#required-ports)
  (80, 8080, 24567).
- *(Optional)* a DNS A record per IP. Recommended if you want to
  re-IP later without rotating operator-side configuration.

## Architecture overview

Use **one `dstack-vmm`** to host both CVMs. Each CVM binds its
port-forwards to a distinct host IP via the per-port-mapping
`host_address` field, so the two nodes are independently reachable
on the public internet on the canonical port `:24567`.

```
                 Host (bare-metal TDX)
+-------------------------------------------------------------+
|                                                             |
|   public IP_M (e.g. 203.0.113.10)   public IP_T (e.g. .11)  |
|         ^                                  ^                |
|         |                                  |                |
|   hostfwd :24567 -> CVM_M           hostfwd :24567 -> CVM_T |
|         |                                  |                |
|   +-----------+                      +-----------+          |
|   |  qemu CVM |                      |  qemu CVM |          |
|   |  mainnet  |                      |  testnet  |          |
|   +-----^-----+                      +-----^-----+          |
|         |                                  |                |
|         +-----------------+----------------+                |
|                           |                                 |
|                     dstack-vmm                              |
|                     RPC :10000                              |
|                                                             |
|       shared by EVERY CVM on this host:                     |
|       - SGX sealing-key-provider                            |
|       - PCCS endpoint(s)                                    |
|       - dstack-vmm itself                                   |
+-------------------------------------------------------------+
```

Key properties:

- One `dstack-vmm` process and `vmm.toml` — same as a single-node
  deployment.
- Each CVM specifies `host_address` per port mapping at creation
  time, so its `:24567` / `:80` / `:8080` forwards land on a
  distinct host IP.
- The **SGX sealing-key-provider, PCCS endpoints, and `dstack-vmm`
  itself are shared by every CVM on this host** — they're host-level
  services, not per-CVM. Because MPC's deploy passes
  `--no-instance-id` to dstack (for consistent TDX measurements
  across operators), two CVMs running the same launcher image derive
  the **same** sealing key. Each CVM still has its own
  per-CVM working directory under the shared `dstack-vmm`, so on-disk
  data is isolated per CVM — the keys themselves just aren't per-CVM.

> **Two `dstack-vmm` instances are also a valid alternative.** Run
> one per CVM (separate working directories, distinct
> `address`/`port`/`cid_start`, each in its own systemd scope) if
> you want independent control planes — for example, to apply
> distinct resource limits via systemd cgroup properties, or for
> symmetry with single-node hosts. The setup is otherwise the same
> as below; you just point each web UI / CLI at its own
> `dstack-vmm`. For most operators the simpler one-`dstack-vmm`
> path is enough.

## Setup walkthrough

Assumes you've completed the single-node
[TDX and Dstack Setup](./running-an-mpc-node-in-tdx-external-guide.md#tdx-and-dstack-setup)
and have one working CVM. The steps below add a second CVM on the
same host, sharing the same `dstack-vmm`.

### Step 1 — Plan IPs

Pick which public host IP each chain will bind to. For the rest of
this guide:

| Chain | Host IP | Ports (host & CVM) |
|---|---|---|
| mainnet | `203.0.113.10` (`IP_M`) | `:24567`, `:80`, `:8080` |
| testnet | `203.0.113.11` (`IP_T`) | `:24567`, `:80`, `:8080` |

Both CVMs use the same canonical ports — `host_address` is what
disambiguates them on the host side.

### Step 2 — Create the second CVM

The first CVM is the one you already created via the single-node
walkthrough. In the same dstack-vmm web UI (`http://127.0.0.1:10000`),
create the second CVM following
[Configuring and starting the MPC binary in a CVM](./running-an-mpc-node-in-tdx-external-guide.md#configuring-and-starting-the-mpc-binary-in-a-cvm).

For **each port forward** (`:80`, `:8080`, `:24567`), set the **host
address** to that CVM's assigned IP. The dstack-vmm web UI exposes
this field next to host port / VM port at CVM-creation time.

### Step 3 — Per-CVM `user-config.toml`

The two CVMs use the same launcher image but **different**
`user-config.toml` content. Deltas from the
[single-node example](./running-an-mpc-node-in-tdx-external-guide.md#prepare-mpc-node-configuration)
— each field lives in a different section of `user-config.toml`, so
follow the [template](https://github.com/near/mpc/blob/main/deployment/cvm-deployment/user-config.toml)
for the right placement:

| Field | Mainnet | Testnet |
|---|---|---|
| `chain_id` | `"mainnet"` | `"testnet"` |
| `mpc_contract_id` | `"v1.signer"` | `"v1.signer-prod.testnet"` |
| `near_boot_nodes` | mainnet boot list | testnet boot list |
| `tier3_public_addr` | `"203.0.113.10:24567"` (`IP_M`) | `"203.0.113.11:24567"` (`IP_T`) |
| `my_near_account_id` | your mainnet account | your testnet account |

`tier3_public_addr` is **required** here — without it the second
node's auto-discovery would collapse to the host's default-route
outbound IP and Tier3 state-sync would fail. See the
[`tier3_public_addr` / `external_storage_fallback_threshold` bullets](./running-an-mpc-node-in-tdx-external-guide.md#prepare-mpc-node-configuration)
in the single-node guide for the full field semantics.

## Operational considerations

- **Monitoring.** Each CVM exposes `:8080/metrics` on its own host
  IP. Configure scraping per node.
- **Image upgrades.** Each CVM is upgraded independently from the
  same dstack-vmm web UI. Voting on mainnet vs testnet image hashes
  is a per-chain decision; the contract enforces it per-chain
  anyway.
- **Resource isolation.** CVMs are independent qemu processes, so
  per-CVM resource use is naturally isolated at the OS level. If
  you need hard caps, the simplest path is host-level cgroup v2
  controls on each qemu process. (The two-`dstack-vmm` alternative
  above gives each CVM its own systemd scope, which is more
  ergonomic for this.)

## What's NOT supported on this setup

- **Single-IP hosts.** Two MPC nodes can't share `:24567` on the
  same host IP unless one uses a non-canonical port, which
  complicates DNS / firewall rules. You need ≥ 2 routable IPs.
- **Tier2 inbound peer recovery.** Both CVMs egress with the same
  outbound source IP under slirp, so their gossiped `PeerInfo`
  collides — peers dialing inbound by gossiped address can only
  reach one of them. **This is acceptable**: the MPC node functions
  correctly outbound-only. Tier2 inbound is good network
  citizenship, not a functional requirement.
