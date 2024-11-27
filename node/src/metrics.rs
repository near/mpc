use lazy_static::lazy_static;

lazy_static! {
    pub static ref MPC_NUM_TRIPLES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_triples_generated",
            "Number of triples generated (including both owned and not owned)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_TRIPLES_AVAILABLE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_triples_available",
            "Number of triples generated that we own, and not yet used"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_PRESIGNATURES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_presignatures_generated",
            "Number of presignatures generated (including both owned and not owned)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_available",
            "Number of presignatures generated that we own, and not yet used"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGNATURES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signatures_generated",
            "Number of signatures generated (initiated by either us or someone else)"
        )
        .unwrap();
}
