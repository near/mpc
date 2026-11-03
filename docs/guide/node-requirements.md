# MPC node requirements

TEE hosts have additional requirements (c.f. [Prerequisites and Requirements](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#prerequisites-and-requirements))


## Resources

| Resource | Minimum |
|---|---|
| Network | 1 Gbps download, 1 Gbps upload (sustained committed rate, not NIC link speed) |
| Memory | 64 GB |
| (v)Cores | 8 |
| Disk | 1 TB (1000 GB), SSD NVMe or equivalent |

## Ports

MPC nodes bind a fixed set of ports:

| Port | Purpose |
|---|---|
| **80** | Node-to-node communication (port override convention) |
| **8080** | Debug and telemetry collection, plus the `/public_data` endpoint |
| **8079** | Migration port |
| **24567** | Embedded-node builds only: decentralized state sync |
| **3030** | Embedded-node builds only: nearcore RPC, including nearcore's own metrics |

Firewall: allow ingress on ports 80 (MPC), 8080 (web) and 8079 (migration). Embedded-node
builds also need 24567 (near).

## NEAR RPC endpoint

The node reads the chain from a NEAR node that serves `EXPERIMENTAL_indexer_block`; see
[HTTP indexing](http-indexer.md) for the settings that node needs. Run it under your own
operational control: the MPC node trusts it for chain state.

## Public IP

Assign a static public IP. A DNS A record is optional but recommended — it gives you room to
move if the IP changes or you need to fail over
([Namecheap](https://www.namecheap.com/support/knowledgebase/article.aspx/319/2237/how-can-i-set-up-an-a-address-record-for-my-domain/),
[Cloudflare](https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/)).

## Software

[`near-cli-rs`](https://github.com/near/near-cli-rs) — install per the upstream README; the
`near` binary must be on your `$PATH`.
