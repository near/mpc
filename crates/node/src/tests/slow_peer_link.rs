//! Experiment for #4764: node 0 reaches node 1 through a proxy limited to
//! [`LINK_BYTES_PER_SEC`] and queues more bulk asset-generation traffic than the link drains
//! during the run. Node 0 must stay in node 1's alive set, so its indexer heights must not wait
//! behind that backlog.
//!
//! Timing-sensitive and about a minute long, so it is `#[ignore]`d. Run it with:
//! ```text
//! RUST_LOG=off cargo nextest run --cargo-profile=test-release -p mpc-node \
//!     slow_peer_link --run-ignored all --no-capture
//! ```

use crate::network::wire_format::EcdsaTaskId;
use crate::network::{MeshNetworkClient, MeshNetworkTransportSender, run_network_client};
use crate::p2p::new_tls_mesh_network;
use crate::p2p::testing::{generate_test_p2p_configs, port_seed};
use crate::primitives::UniqueId;
use crate::tracking::{AutoAbortTask, testing::start_root_task_with_periodic_dump};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;
use tokio::time::Instant;

const LINK_BYTES_PER_SEC: u64 = 300 * 1024;
/// Keeps the backlog in node 0's socket rather than in the proxy, as on a window-limited path.
const PROXY_RECV_BUFFER_BYTES: u32 = 64 * 1024;
const PROXY_CHUNK_BYTES: usize = 4 * 1024;

/// About 1.7 blocks per second, the mainnet pace.
const BLOCK_TIME: Duration = Duration::from_millis(600);
const STARTING_HEIGHT: u64 = 1_000;

const BULK_FRAMES: usize = 80;
const BULK_MESSAGES_PER_FRAME: usize = 64;
const BULK_MESSAGE_BYTES: usize = 4 * 1024;

const WARMUP: Duration = Duration::from_secs(3);
const MEASUREMENT: Duration = Duration::from_secs(60);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(200);

#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[ignore = "timing-sensitive experiment for #4764; run manually with --run-ignored"]
#[expect(non_snake_case)]
async fn slow_peer_link__should_keep_peer_alive_while_bulk_traffic_saturates_it() {
    start_root_task_with_periodic_dump(async move {
        // Given
        let mut configs = generate_test_p2p_configs(
            &["test0".parse().unwrap(), "test1".parse().unwrap()],
            2,
            &port_seed::SLOW_PEER_LINK_TEST,
        )
        .unwrap();
        let p0 = configs[0].0.my_participant_id;
        let p1 = configs[1].0.my_participant_id;
        let participants = vec![p0, p1];

        let p1_in_node0_config = configs[0]
            .0
            .participants
            .participants
            .iter_mut()
            .find(|participant| participant.id == p1)
            .unwrap();
        let node1_address: SocketAddr = format!("127.0.0.1:{}", p1_in_node0_config.port)
            .parse()
            .unwrap();
        let (proxy_port, _proxy) = must_spawn_throttling_proxy(node1_address).await;
        p1_in_node0_config.port = proxy_port;

        let (sender0, receiver0) = new_tls_mesh_network(&configs[0].0, &configs[0].1)
            .await
            .unwrap();
        let (sender1, receiver1) = new_tls_mesh_network(&configs[1].0, &configs[1].1)
            .await
            .unwrap();
        sender0.wait_for_ready(2, &participants).await.unwrap();
        sender1.wait_for_ready(2, &participants).await.unwrap();
        let (client0, _channels0, _tasks0) =
            run_network_client(Arc::new(sender0), Box::new(receiver0));
        // Unread, so node 1's end of the bulk channel stays open and buffers the backlog.
        let (client1, _channels1, _tasks1) =
            run_network_client(Arc::new(sender1), Box::new(receiver1));

        let _heights = advance_heights(vec![client0.clone(), client1.clone()]);
        tokio::time::sleep(WARMUP).await;

        // When
        let bulk = client0
            .new_channel_for_task(
                EcdsaTaskId::ManyTriples {
                    start: UniqueId::new(p0, 0, 0),
                    count: 64,
                },
                participants,
            )
            .unwrap();
        for _ in 0..BULK_FRAMES {
            bulk.sender()
                .send(
                    p1,
                    vec![vec![0u8; BULK_MESSAGE_BYTES]; BULK_MESSAGES_PER_FRAME],
                )
                .unwrap();
        }

        let mut max_lag = 0;
        let mut samples = 0;
        let mut samples_not_alive = 0;
        let mut first_not_alive_after = None;
        let start = Instant::now();
        while start.elapsed() < MEASUREMENT {
            let heights = client1.get_indexer_heights();
            max_lag = max_lag.max(heights[&p1].saturating_sub(heights[&p0]));
            samples += 1;
            if !client1.all_alive_participant_ids().contains(&p0) {
                samples_not_alive += 1;
                first_not_alive_after.get_or_insert(start.elapsed());
            }
            tokio::time::sleep(SAMPLE_INTERVAL).await;
        }

        // Then
        println!(
            "[#4764] max lag of node 0's height at node 1: {max_lag} blocks; node 0 missing \
             from node 1's alive set in {samples_not_alive}/{samples} samples, first after \
             {first_not_alive_after:?}",
        );
        assert_eq!(samples_not_alive, 0);
    })
    .await;
}

/// Accepts connections on a fresh local port and forwards each to `upstream`, pacing the
/// direction towards `upstream` at [`LINK_BYTES_PER_SEC`].
async fn must_spawn_throttling_proxy(upstream: SocketAddr) -> (u16, AutoAbortTask<()>) {
    let socket = TcpSocket::new_v4().unwrap();
    socket
        .set_recv_buffer_size(PROXY_RECV_BUFFER_BYTES)
        .unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(16).unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        while let Ok((client, _)) = listener.accept().await {
            connections.spawn(forward_throttled(client, upstream));
        }
    });
    (port, task.into())
}

async fn forward_throttled(client: TcpStream, upstream: SocketAddr) {
    let Ok(server) = TcpStream::connect(upstream).await else {
        return;
    };
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let paced = async {
        let start = Instant::now();
        let mut forwarded: u64 = 0;
        let mut buf = vec![0u8; PROXY_CHUNK_BYTES];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if server_write.write_all(&buf[..n]).await.is_err() {
                return;
            }
            forwarded += u64::try_from(n).unwrap();
            let due = Duration::from_nanos(forwarded * 1_000_000_000 / LINK_BYTES_PER_SEC);
            tokio::time::sleep_until(start + due).await;
        }
    };
    let unpaced = tokio::io::copy(&mut server_read, &mut client_write);
    tokio::select! {
        _ = paced => {}
        _ = unpaced => {}
    }
}

fn advance_heights(clients: Vec<Arc<MeshNetworkClient>>) -> AutoAbortTask<()> {
    tokio::spawn(async move {
        let mut height = STARTING_HEIGHT;
        loop {
            for client in &clients {
                client.update_indexer_height(height);
            }
            height += 1;
            tokio::time::sleep(BLOCK_TIME).await;
        }
    })
    .into()
}
