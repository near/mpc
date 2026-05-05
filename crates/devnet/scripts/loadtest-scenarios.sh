#!/usr/bin/env bash
# Drive `mpc-devnet loadtest run` through a fixed set of load-shape scenarios
# against an MPC contract (defaults to the testnet `v1.signer-prod.testnet`).
#
# Each scenario is just a `mpc-devnet loadtest <name> run` invocation with a
# different `--qps` / `--duration`.  Output is streamed to stdout — pipe to
# `tee` yourself if you want to keep a transcript.
#
# Prerequisites:
#   * `mpc-devnet` is installed (see crates/devnet/README.md).
#   * A loadtest setup has been created with `mpc-devnet loadtest <name> new ...`
#     and has enough access keys to sustain the highest QPS used below
#     (a single account with 16 keys is usually enough up to ~20 QPS).
#   * The parallel-sign helper contract is deployed
#     (`mpc-devnet loadtest <name> deploy-parallel-sign-contract`).
#
# Usage:
#   ./loadtest-scenarios.sh <loadtest-name> [options]
#
# Options:
#   --contract <id>    MPC contract to target (default: v1.signer-prod.testnet)
#   --domain <id>      Domain id to sign against (default: 0)
#   --batch <n>        Sigs per parallel-sign tx (default: 10). Each scenario's
#                      `--qps` is the target signature rate; the loadtest sends
#                      `qps/batch` RPC txs/sec, so a higher batch lowers RPC
#                      pressure for the same signature throughput.
#   --scenario <name>  One of: sustained, high, spike, all (default: all)
#   -h, --help         Show this message

set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
}

CONTRACT="v1.signer-prod.testnet"
DOMAIN=0
BATCH=10
SCENARIO="all"
LOADTEST_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --contract)  CONTRACT="$2"; shift 2;;
        --domain)    DOMAIN="$2"; shift 2;;
        --batch)     BATCH="$2"; shift 2;;
        --scenario)  SCENARIO="$2"; shift 2;;
        -h|--help)   usage; exit 0;;
        -*) echo "unknown argument: $1" >&2; usage; exit 1;;
        *)
            if [[ -n "$LOADTEST_NAME" ]]; then
                echo "unexpected positional argument: $1" >&2
                usage
                exit 1
            fi
            LOADTEST_NAME="$1"
            shift
            ;;
    esac
done

if [[ -z "$LOADTEST_NAME" ]]; then
    echo "missing required <loadtest-name>" >&2
    usage
    exit 1
fi

case "$SCENARIO" in
    sustained|high|spike|all) ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 1;;
esac

echo "loadtest setup : $LOADTEST_NAME"
echo "target contract: $CONTRACT"
echo "domain id      : $DOMAIN"
echo "batch          : $BATCH sigs per parallel-sign tx"
echo "scenario       : $SCENARIO"
echo

run_scenario() {
    local label="$1" qps="$2" duration="$3"
    echo "[$(date -Is)] >>> scenario '$label': ${qps} sigs/s (${BATCH}/tx) for ${duration}s"
    mpc-devnet loadtest "$LOADTEST_NAME" run \
        --mpc-contract "$CONTRACT" \
        --parallel-sign-calls-per-domain "${DOMAIN}=${BATCH}" \
        --qps "$qps" \
        --duration "$duration"
    echo "[$(date -Is)] <<< scenario '$label' done"
    echo
}

# Acceptance criterion from near/mpc-private#320 is "sustained load of at
# least 100 transactions per minute".  2 sigs/s = 120 tpm; 10 minutes gives
# 1200 signatures which is enough to see whether the failure rate is
# stable over time.
scenario_sustained() { run_scenario sustained 2 600; }

# A higher steady-state to see how the network behaves well above the
# acceptance bar.  10 sigs/s = 600 tpm for 5 minutes.
scenario_high() { run_scenario high 10 300; }

# Spike: low baseline -> burst -> low baseline.  This is what the issue
# explicitly asks us to try ("submit spikes of transactions").  The cool-
# down at the end lets us see whether the network drains pending work
# without lingering failures.
scenario_spike() {
    run_scenario spike-warm  2  60
    run_scenario spike-burst 10 60
    run_scenario spike-cool  2  60
}

# Pause between scenarios so the RPC provider's rate-limit window can
# reset before the next scenario starts hammering it.
COOLDOWN_SECS=60

case "$SCENARIO" in
    sustained) scenario_sustained;;
    high)      scenario_high;;
    spike)     scenario_spike;;
    all)
        scenario_sustained
        echo "[$(date -Is)] cooldown ${COOLDOWN_SECS}s before next scenario"
        sleep "$COOLDOWN_SECS"
        scenario_high
        echo "[$(date -Is)] cooldown ${COOLDOWN_SECS}s before next scenario"
        sleep "$COOLDOWN_SECS"
        scenario_spike
        ;;
esac

echo "all scenarios complete."
