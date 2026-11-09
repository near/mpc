//! Foreign chain RPC provider health check: [`probe::probe_all_providers`] asks every configured
//! provider which network it serves and compares the answer against the operator's
//! `expected_network_fingerprint`. The node runs it periodically, the config tester once.

pub mod probe;
