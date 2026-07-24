<!--
This file is synced to near/mpc (deployment/grafana/README.md) by the
grafana_dashboard_export workflow in the private Near-One/infra-ops
repository. Edit it there, not in near/mpc — manual changes in near/mpc
will be overwritten by the next sync PR.
-->

# Grafana dashboards

Import-ready JSON exports of the Grafana dashboards Near One uses to
operate its MPC nodes. Datasource references are templatized, so the
dashboards can be imported into any Grafana instance and mapped to your
own Prometheus.

The files in this directory are generated and kept up to date
automatically: whenever a dashboard changes in Near One's Grafana, a
bot PR updates the export here. Please do not edit them by hand — open
an issue or contact the Near One team if you want a dashboard changed.

## Importing into your Grafana

1. In Grafana: **Dashboards → New → Import → Upload dashboard JSON file**.
2. When prompted, select your **Prometheus** datasource for the
   templatized input(s).
3. Click **Import**.

The exports keep the original dashboard UID, so importing a newer
revision of the same file replaces your previous copy.

## Metric requirements (multichain-mpc-cluster)

The panels only render if your Prometheus scrapes the mpc-node and NEAR
node metrics with a compatible label scheme:

- `up` series carrying `binary="mpc-node"` and a `chain_id` label
  (e.g. `mainnet`, `testnet`) — the `chain_id` dashboard variable is
  populated from `label_values(up{binary="mpc-node"}, chain_id)`.
- mpc-node metrics (`mpc_*`) and NEAR node metrics such as
  `near_block_height_head`, all labeled with `chain_id`.
- Several queries additionally filter on
  `job=~"mpc_operators|multichain"`; adjust your scrape job names or
  edit those queries after import.
