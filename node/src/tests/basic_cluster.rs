use crate::p2p::testing::PortSeed;
use crate::tests::{request_signature_and_await_response, IntegrationTestSetup};
use crate::tracking::AutoAbortTask;
use lazy_static::lazy_static;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;
use serial_test::serial;
use stats_alloc::{StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;
use tokio::time::sleep;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
#[serial]
async fn test_basic_cluster() {
    init_integration_logger();
    let region = stats_alloc::Region::new(&GLOBAL);
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::BASIC_CLUSTER_TEST,
    );

    let domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    for i in 0..60 {
        sleep(std::time::Duration::from_secs(1)).await;
        let stats = region.change();
        println!("Stats at {}: {:#?}", i, stats);
        MEMORY_ALLOC_STATS
            .with_label_values(&["allocations"])
            .set(stats.allocations as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["deallocations"])
            .set(stats.deallocations as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["reallocations"])
            .set(stats.reallocations as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["bytes_allocated"])
            .set(stats.bytes_allocated as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["bytes_deallocated"])
            .set(stats.bytes_deallocated as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["bytes_reallocated"])
            .set(stats.bytes_reallocated as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["alive_allocs"])
            .set((stats.allocations - stats.deallocations) as i64);
        MEMORY_ALLOC_STATS.with_label_values(&["alive_bytes"]).set(
            stats.bytes_allocated as i64 + stats.bytes_reallocated as i64
                - stats.bytes_deallocated as i64,
        );
    }

    setup.indexer.disable("test2".parse().unwrap()).await;
    setup.indexer.disable("test3".parse().unwrap()).await;
    setup
        .indexer
        .contract_mut()
        .await
        .add_domains(vec![DomainConfig {
            id: DomainId(1),
            scheme: SignatureScheme::Secp256k1,
        }]);

    for i in 60..600 {
        sleep(std::time::Duration::from_secs(1)).await;
        let stats = region.change();
        println!("Stats at {}: {:#?}", i, stats);
        MEMORY_ALLOC_STATS
            .with_label_values(&["allocations"])
            .set(stats.allocations as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["deallocations"])
            .set(stats.deallocations as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["reallocations"])
            .set(stats.reallocations as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["bytes_allocated"])
            .set(stats.bytes_allocated as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["bytes_deallocated"])
            .set(stats.bytes_deallocated as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["bytes_reallocated"])
            .set(stats.bytes_reallocated as i64);
        MEMORY_ALLOC_STATS
            .with_label_values(&["alive_allocs"])
            .set((stats.allocations - stats.deallocations) as i64);
        MEMORY_ALLOC_STATS.with_label_values(&["alive_bytes"]).set(
            stats.bytes_allocated as i64 + stats.bytes_reallocated as i64
                - stats.bytes_deallocated as i64,
        );
    }
}

lazy_static! {
    pub static ref MEMORY_ALLOC_STATS: prometheus::IntGaugeVec =
        prometheus::register_int_gauge_vec!(
            "mpc_memory_alloc_stats",
            "Memory allocation statistics",
            &["stat"],
        )
        .unwrap();
}
