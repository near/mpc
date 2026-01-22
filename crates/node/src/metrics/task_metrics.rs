use std::sync::LazyLock;

use tokio_metrics::TaskMonitor;

pub(crate) const ECDSA_TASK_MONITORS: LazyLock<EcdsaTaskMonitors> =
    LazyLock::new(|| EcdsaTaskMonitors::default());

pub(crate) const ROBUST_ECDSA_TASK_MONITORS: LazyLock<RobustEcdsaTaskMonitors> =
    LazyLock::new(|| RobustEcdsaTaskMonitors::default());

pub(crate) const EDDSA_TASK_MONITORS: LazyLock<EddsaTaskMonitors> =
    LazyLock::new(|| EddsaTaskMonitors::default());

#[derive(Default)]
pub(crate) struct EcdsaTaskMonitors {
    pub(crate) make_signature: TaskMonitor,
    pub(crate) make_signature_follower: TaskMonitor,

    pub(crate) triple_generation: TaskMonitor,
    pub(crate) triple_generation_follower: TaskMonitor,

    pub(crate) presignature_generation_leader: TaskMonitor,
    pub(crate) presignature_generation_follower: TaskMonitor,
}

#[derive(Default)]
pub(crate) struct RobustEcdsaTaskMonitors {
    pub(crate) make_signature: TaskMonitor,
    pub(crate) make_signature_follower: TaskMonitor,

    pub(crate) presignature_generation_leader: TaskMonitor,
    pub(crate) presignature_generation_follower: TaskMonitor,
}

#[derive(Default)]
pub(crate) struct EddsaTaskMonitors {
    pub(crate) make_signature: TaskMonitor,
    pub(crate) make_signature_follower: TaskMonitor,
}
