use test_port_allocator::{E2ePortSpace, TestPorts};

/// Deterministic per-`test_id` port allocator for E2E clusters: [`TestPorts`] on
/// the [`E2ePortSpace`] layout.
pub type E2ePortAllocator = TestPorts<E2ePortSpace>;
