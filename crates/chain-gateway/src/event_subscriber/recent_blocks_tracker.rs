use near_indexer_primitives::CryptoHash;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::event_subscriber::block_events::BlockContext;
use crate::event_subscriber::metrics::{MPC_BLOCKS_INDEXED, MPC_FINALIZED_BLOCKS_INDEXED};
use crate::types::BlockHeight;

/// Tracks the topology of the recent blocks, using the blocks given by the indexer.
///
/// This class provides two important functionalities:
///  - Converts a stream of optimistic blocks from the indexer into a stream of finalized
///    blocks.
///  - For each block added via `add_block`, it returns a `BlockStatusHandle` that can be
///    used to observe that block's current `BlockStatus` (non-canonical, canonical or final).
///
/// This class provides the following invariants (provided the requirements listed below are met):
///  - A block that is final will never be reverted to non-final;
///  - Any block that is currently tracked has the potential to become final. In other words,
///    the tracker removes non-final blocks of height less or equal to the latest final height.
///
/// In order to guarantee above invariants, we have certain expectations of the order of blocks
/// that come from the indexer.
/// First, let's define a partial order for blocks. For any two blocks A and B:
///  - If A is a strict ancestor of B then A < B;
///  - If B is a strict ancestor of A then B < A;
///  - If A is the same block as B then A = B;
///  - Otherwise, A and B are not ordered.
///
/// We expect that the blocks given by the indexer:
///  - Respects partial order. That is, if A is given before B, it must not happen that A > B.
///  - Furthermore, if A < B and B < C, and both A and C are given, then B must also be given.
///    In other words there should not be any gaps.
///
/// That being said, the following is fair game:
///  - The indexer gives blocks of different forks in any order, i.e. it can give a block of
///    height 12 and then another block of height 10 that belongs to a different fork.
///  - The indexer, upon startup, may start giving blocks from any position in the blockchain,
///    including giving blocks from multiple forks without giving us any common parents.
///  - The indexer may skip block heights, meaning a block at height h can have a child at height
///    h+m, for any m>0.
///
/// Given these expectations, we provide the aforementioned functionalities by tracking the
/// following:
///  - We keep a fixed-sized window of recent blocks, i.e. all blocks with height >= H - W + 1,
///    where H is the height of the latest block we have seen, and W is the window size.
///  - We keep track of the canonical chain as well as the final chain.
///
/// Despite the assumptions we make on the indexer's behavior, this class guarantees not to panic
/// even if the indexer violates these assumptions in arbitrary ways.
///
/// Note that the `RecentBlocksTracker` is removing blocks aggressively. A block is removed if one
/// of the following conditions is met:
///  - The block sits on a dead fork and can't ever be finalized;
///  - The block is outside of the recency window `RecentBlocksTracker::window_size`
///
/// Cleanup takes place after every `add_block` in two methods:
///  - `maybe_update_final_head` owns **dead-fork cleanup**. When a new final block is established,
///    every subtree that can't be part of the final chain — non-final siblings of the final chain
///    at any height, and any `root_children` subtree not on the final chain with height ≤ the new
///    final-head height — is dropped. This is the "Dead-fork prune at X" annotation in
///    the picture below.
///  - `prune_old_blocks` owns **recency-window prune**. Any node below `min_height_to_keep` is
///    dropped; its in-window descendants become new roots. This is the "Recency window prune"
///    annotation below.
///
/// **Example.** If block 11 is the latest final block, both cleanups together produce the picture
/// below. `root_1`, `root_2`, and the `(8)`/`(10)` subtrees are dropped as dead forks; `(4F)` is
/// dropped by the recency window; `(7F)` becomes the new single root of the kept tree.
///
/// ```text
///  ---------------------------┐
///     These blocks will       ┆
///     never be included       ┆
///                             ┆
///   root 1   root 2           ┆ root 3
///   (1)                       ┆              Dead-fork prune at (1)
///    │        (2)             ┆              Dead-fork prune at (2)
///   (3)        │              ┆
///    │         │              ┆ (4F)         Recency window prune node (4F)
///  ┌─┴─┐       │       ┌──────────┴─┐
/// ════════════════════════════════════════ ← cutoff (h ≥ min_height_to_keep)
/// (5)  │       │       │      ┆     │
///  │   │       │       │      ┆    (7F)      (7F) becomes new root
///  │   │       │       │   ┌────────┴─┐
///  │  (6)      │       │   │  ┆       │
///  │   │       │       │  (8) ┆       │      Dead-fork prune at (8)
///  │   │       │       │   │  ┆     (9F)
///  │   │       │      (10) │  ┆       │      Dead-fork prune at (10)
///  │   │       │       │   │  ┆     (11F)    ← latest final block height
///  │   │       │       │   │  ┆       │
///  │   │       │       │   │  ┆     (12)
///  │   │       │      (13) │  ┆       │
///  │   │       │       │   │  ┆       │
///  ..  ..      ..      ..  .. ┆       ..
/// ```
pub struct RecentBlocksTracker {
    window_size: u64,
    /// By "root", we mean the blocks whose parents we don't know or are older than the window.
    /// The children of the root are the earliest blocks we are keeping who do not have any order
    /// with each other.
    root_children: Vec<Arc<BlockNode>>,
    /// The head of the canonical chain. This is the chain of the highest-height block we've seen.
    /// This may be None if we have no block at all.
    canonical_head: Weak<BlockNode>,
    /// The head of the final chain. This is determined by recovering information from the
    /// last_final_block fields of the block headers given to us. This may be None if we have not
    /// seen any final blocks yet.
    final_head: Option<Arc<BlockNode>>,
    /// The maximum height of any block we have been given via `add_block`.
    maximum_height_available: BlockHeight,
    /// Maps block hashes to their nodes in the tree.
    hash_to_node: HashMap<CryptoHash, Arc<BlockNode>>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    /// The block is optimistically included in the chain, but it is not on the canonical chain.
    OptimisticButNotCanonical = 0,
    /// The block is optimistically included in the chain, and it is on the canonical chain,
    /// but it is not yet part of the final chain.
    /// Note that if two chains tie for canonical height, the first one seen is considered the
    /// canonical chain (c.f. `RecentBlocksTracker::update_canonical_head`).
    OptimisticAndCanonical = 1,
    /// The block is finalized by the blockchain.
    /// It is an ancestor (including self) of the latest final block.
    Final = 2,
}

impl From<BlockStatus> for u8 {
    fn from(status: BlockStatus) -> Self {
        status as u8
    }
}

struct AtomicBlockStatus(AtomicU8);

impl AtomicBlockStatus {
    fn is_final(&self) -> bool {
        self.0.load(Ordering::Relaxed) == u8::from(BlockStatus::Final)
    }

    fn is_canonical(&self) -> bool {
        let status = self.0.load(Ordering::Relaxed);
        status == u8::from(BlockStatus::OptimisticAndCanonical)
            || status == u8::from(BlockStatus::Final)
    }

    fn make_final(&self) {
        self.0.store(BlockStatus::Final.into(), Ordering::Relaxed);
    }

    fn make_canonical(&self) {
        if self.is_final() {
            tracing::error!(
                "received invalid data from indexer. Downgrading from final to canonical is not possible"
            );
            return;
        }
        self.0.store(
            BlockStatus::OptimisticAndCanonical.into(),
            Ordering::Relaxed,
        );
    }

    fn make_non_canonical(&self) {
        if self.is_final() {
            tracing::error!(
                "received invalid data from indexer. Downgrading from final to non-canonical is not possible"
            );
            return;
        }
        self.0.store(
            BlockStatus::OptimisticButNotCanonical.into(),
            Ordering::Relaxed,
        );
    }
}

/// A handle to a block's status held by the [`RecentBlocksTracker`].
///
/// Consumers can read the current finality status but cannot hold a strong
/// reference to the underlying atomic. Pruning a block from the tracker
/// drops its ref count to zero.
#[derive(Clone)]
pub struct BlockStatusHandle(Weak<AtomicBlockStatus>);

impl BlockStatusHandle {
    /// `None` if the block has been pruned from the tracker.
    pub fn is_final(&self) -> Option<bool> {
        self.0.upgrade().map(|s| s.is_final())
    }

    /// `None` if the block has been pruned from the tracker.
    pub fn is_canonical(&self) -> Option<bool> {
        self.0.upgrade().map(|s| s.is_canonical())
    }
}

pub struct AddBlockResult {
    pub block_status: BlockStatusHandle,
}

/// Represents a block in the recent blockchain.
struct BlockNode {
    hash: CryptoHash,
    height: BlockHeight,
    /// Indicates the finality status of this block. Held as `Arc`.
    /// A [`BlockStatusHandle`] is handed out via [`AddBlockResult::block_status`] to consumers,
    /// allowing them to observe status changes and detect pruning.
    status: Arc<AtomicBlockStatus>,
    /// The parent block, if we're aware of it. This may be None if we have never
    /// heard of the parent.
    /// The Weak becomes a dangling pointer when the parent is pruned.
    parent: Option<Weak<BlockNode>>,
    /// The children blocks; there can be multiple if there are forks. The children are
    /// kept in no specific order.
    children: Mutex<Vec<Arc<BlockNode>>>,
}

impl BlockNode {
    fn get_parent(&self) -> Option<Arc<BlockNode>> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    fn status_handle(&self) -> BlockStatusHandle {
        BlockStatusHandle(Arc::downgrade(&self.status))
    }

    fn keep_only_child(
        &self,
        child_to_retain: &Arc<BlockNode>,
        subtrees_to_remove: &mut VecDeque<Arc<BlockNode>>,
    ) {
        let mut children = self.children.lock().expect("lock must not be poisoned");
        for child in children.iter() {
            if !Arc::ptr_eq(child, child_to_retain) {
                subtrees_to_remove.push_back(child.clone());
            }
        }
        *children = vec![child_to_retain.clone()];
    }

    fn debug_print(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        indents: &mut Vec<u8>,
        final_head: Option<CryptoHash>,
        canonical_head: Option<CryptoHash>,
    ) -> std::fmt::Result {
        if Some(self.hash) == final_head {
            write!(f, "FH ")?;
        } else if Some(self.hash) == canonical_head {
            write!(f, "CH ")?;
        } else {
            write!(f, "   ")?;
        }
        for indent in indents.iter() {
            match *indent {
                0 => write!(f, "  ")?,
                1 => write!(f, "│ ")?,
                2 => write!(f, "└─")?,
                3 => write!(f, "├─")?,
                _ => unreachable!(),
            }
        }
        if indents.last().is_some_and(|indent| *indent >= 2) {
            *indents.last_mut().unwrap() -= 2;
        }
        write!(
            f,
            "[{}] {} {} {:<44} ",
            self.height,
            if self.status.is_canonical() { "C" } else { " " },
            if self.status.is_final() { "F" } else { " " },
            format!("{:?}", self.hash),
        )?;
        writeln!(f)?;
        let children = self.children.lock().unwrap();
        for (i, child) in children.iter().enumerate() {
            if children.len() == 1 {
                child.debug_print(f, indents, final_head, canonical_head)?;
            } else {
                let indent = if i + 1 == children.len() { 2 } else { 3 };
                indents.push(indent);
                child.debug_print(f, indents, final_head, canonical_head)?;
                indents.pop();
            }
        }
        Ok(())
    }
}

impl RecentBlocksTracker {
    pub fn new(window_size: u64) -> Self {
        Self {
            window_size,
            root_children: Vec::new(),
            canonical_head: Weak::new(),
            final_head: None,
            maximum_height_available: 0.into(),
            hash_to_node: HashMap::new(),
        }
    }

    /// Adds a block to the tracker. This is expected to be called for EVERY block given by the
    /// indexer (whether or not it is interesting).
    pub fn add_block(&mut self, block: &BlockContext) -> AddBlockResult {
        if let Some(node) = self.hash_to_node.get(&block.hash) {
            tracing::error!(
                target: "recent_blocks_tracker",
                "block {:?} already exists at height {}. Incoming height: {}",
                block.hash,
                node.height,
                block.height,
            );
            return AddBlockResult {
                block_status: node.status_handle(),
            };
        }
        MPC_BLOCKS_INDEXED.inc();
        let parent = self.hash_to_node.get(&block.prev_hash).cloned();
        let node = Arc::new(BlockNode {
            hash: block.hash,
            height: block.height,
            status: Arc::new(AtomicBlockStatus(AtomicU8::new(u8::from(
                BlockStatus::OptimisticButNotCanonical,
            )))),
            parent: parent.as_ref().map(Arc::downgrade),
            children: Mutex::new(Vec::new()),
        });
        let block_status = node.status_handle();
        self.hash_to_node.insert(block.hash, node.clone());
        if let Some(parent) = parent {
            parent.children.lock().unwrap().push(node.clone());
        } else {
            self.root_children.push(node.clone());
        }

        let new_final_blocks = self.maybe_update_final_head(block.last_final_block);
        MPC_FINALIZED_BLOCKS_INDEXED.inc_by(
            u64::try_from(new_final_blocks.len())
                .expect("usize should always fit into a u64 on our targets"),
        );
        match self.canonical_head.upgrade() {
            None => {
                // Either the first block ever, or the previous canonical head
                // was removed by the finality cleanup above.
                // We identify the highest tracked node and update the canonical head.
                if let Some(head) = self.highest_tracked_node() {
                    self.update_canonical_head(&head);
                }
            }
            Some(canonical_head) => {
                if block.height > canonical_head.height {
                    self.update_canonical_head(&node);
                }
            }
        }
        if block.height > self.maximum_height_available {
            self.maximum_height_available = block.height;
        }
        self.prune_old_blocks();
        AddBlockResult { block_status }
    }

    /// Advance the final head, mark its ancestors as final, and drop every
    /// subtree that BFT-safety guarantees can no longer be on the final chain.
    /// See `RecentBlocksTracker` for the picture of which subtrees this catches.
    ///
    /// Returns the newly finalized blocks in ascending height order.
    fn maybe_update_final_head(&mut self, potential_final_head: CryptoHash) -> Vec<Arc<BlockNode>> {
        let final_head_node = self.hash_to_node.get(&potential_final_head).cloned();
        let Some(final_head_node) = final_head_node else {
            // We don't track the new final head. Hence, there are no parents whose finality we
            // could update and there are no blocks that we track that become newly finalized.
            // This is expectd to happen when the indexer is starting up.
            return Vec::new();
        };
        let mut new_final_blocks: Vec<Arc<BlockNode>> = Vec::new();
        let mut node = final_head_node.clone();
        let mut subtrees_to_remove: VecDeque<Arc<BlockNode>> = VecDeque::new();
        loop {
            // The node we previously visited is the only final child of `node`.
            if let Some(final_child_of_node) = new_final_blocks.last() {
                node.keep_only_child(final_child_of_node, &mut subtrees_to_remove);
            }
            // If this node is already labeled final, we can exit the loop.
            if node.status.is_final() {
                break;
            }
            // Else, this is a new final node and we visit its parent next.
            node.status.make_final();
            new_final_blocks.push(node.clone());
            let Some(parent) = node.get_parent() else {
                break;
            };
            node = parent;
        }
        // we update the final head if applicable
        if self
            .final_head
            .as_ref()
            .is_none_or(|prev_final_head| prev_final_head.height < final_head_node.height)
        {
            self.final_head = Some(final_head_node.clone());
        }
        // Lastly, we clean up any dead subtrees that live on other branches.
        let new_final_height = final_head_node.height;
        self.update_roots(new_final_height, &mut subtrees_to_remove);
        self.remove_subtrees(subtrees_to_remove);

        new_final_blocks.reverse();
        new_final_blocks
    }

    /// Any root children that sit on dead branches get removed from `self.root_children` and added
    /// to `subtrees_to_remove`
    fn update_roots(
        &mut self,
        new_final_height: BlockHeight,
        subtrees_to_remove: &mut VecDeque<Arc<BlockNode>>,
    ) {
        let mut new_root_children = Vec::new();
        for node in self.root_children.iter() {
            if !node.status.is_final() && node.height <= new_final_height {
                // the entire subtree can be removed
                subtrees_to_remove.push_back(node.clone());
            } else {
                new_root_children.push(node.clone());
            }
        }
        self.root_children = new_root_children;
    }

    fn remove_subtrees(&mut self, mut subtrees_to_remove: VecDeque<Arc<BlockNode>>) {
        while let Some(node) = subtrees_to_remove.pop_front() {
            subtrees_to_remove.extend(
                node.children
                    .lock()
                    .expect("lock must not be poisoned")
                    .drain(..),
            );
            self.hash_to_node.remove(&node.hash);
        }
    }

    /// Updates the canonical chain to the chain of the given block.
    /// Nodes on the existing canonical chain that are not in the new canonical chain
    /// will be marked as no longer canonical.
    fn update_canonical_head(&mut self, new_canonical_head: &Arc<BlockNode>) {
        let mut node = Some(new_canonical_head.clone());

        while let Some(current_node) = node {
            if current_node.status.is_canonical() {
                node = Some(current_node);
                break;
            }
            current_node.status.make_canonical();
            node = current_node.get_parent();
        }
        let common_ancestor = node;

        let mut old_node = self.canonical_head.upgrade();
        while let Some(current_node) = old_node {
            if let Some(common_ancestor) = &common_ancestor
                && Arc::ptr_eq(&current_node, common_ancestor)
            {
                break;
            }
            current_node.status.make_non_canonical();
            old_node = current_node.get_parent();
        }
        self.canonical_head = Arc::downgrade(new_canonical_head);
    }

    /// BFS over the kept tree, returning the highest-height node (insertion order and
    /// BFS order breaks ties). Used to re-elect the canonical head after finality
    /// cleanup sweeps the previous one.
    fn highest_tracked_node(&self) -> Option<Arc<BlockNode>> {
        let mut queue: VecDeque<Arc<BlockNode>> = self.root_children.iter().cloned().collect();
        let mut best: Option<Arc<BlockNode>> = None;
        while let Some(node) = queue.pop_front() {
            if best.as_ref().is_none_or(|b| b.height < node.height) {
                best = Some(node.clone());
            }
            let children = node.children.lock().expect("lock must not be poisoned");
            queue.extend(children.iter().cloned());
        }
        best
    }

    /// Calculates the minimum height of blocks that we need to keep.
    /// This is typically canonical_head.height - window_size + 1, but in case of delayed finality,
    /// we ensure that the final head is not pruned. Otherwise, not only would the logic be very
    /// messy, but also we would not be able to provide a contiguous stream of finalized blocks.
    fn minimum_height_to_keep(&self) -> Option<BlockHeight> {
        let Some(final_head) = &self.final_head else {
            return None;
        };
        Some(
            self.maximum_height_available
                .saturating_sub(self.window_size)
                .saturating_add(1)
                .min(final_head.height),
        )
    }

    /// Recency-window prune. Drops every node below `min_height_to_keep` and
    /// promotes the first in-window descendant on each branch to a new root.
    /// See `RecentBlocksTracker` for the picture; dead-fork cleanup happens in
    /// `maybe_update_final_head`, not here.
    fn prune_old_blocks(&mut self) {
        let Some(min_height_to_keep) = self.minimum_height_to_keep() else {
            return;
        };
        let mut queue: VecDeque<Arc<BlockNode>> = std::mem::take(&mut self.root_children).into();
        let mut new_roots = Vec::new();
        while let Some(node) = queue.pop_front() {
            if node.height >= min_height_to_keep {
                new_roots.push(node);
                continue;
            }
            self.hash_to_node.remove(&node.hash);
            // Drain into the queue so the parent stops holding strong refs to
            // its children — once `hash_to_node` no longer holds the parent,
            // the parent can drop as soon as we move past this iteration.
            let mut children = node.children.lock().expect("lock must not be poisoned");
            queue.extend(children.drain(..));
        }
        self.root_children = new_roots;
    }
}

impl Debug for RecentBlocksTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "   Recent blocks: (Window = {} to {}, GC limit {})",
            self.maximum_height_available
                .saturating_sub(self.window_size)
                .saturating_add(1),
            self.maximum_height_available,
            self.minimum_height_to_keep().unwrap_or(0.into())
        )?;
        let final_head = self.final_head.as_ref().map(|n| n.hash);
        let canonical_head = self.canonical_head.upgrade().map(|n| n.hash);

        for (i, child) in self.root_children.iter().enumerate() {
            child.debug_print(
                f,
                &mut vec![if i + 1 == self.root_children.len() {
                    2
                } else {
                    3
                }],
                final_head,
                canonical_head,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::requests::recent_blocks_tracker::{AtomicBlockStatus, BlockStatusHandle};

    use super::{BlockStatus, RecentBlocksTracker};
    use chain_gateway::event_subscriber::block_events::BlockContext;
    use chain_gateway::types::BlockEntropy;
    use near_indexer::near_primitives::hash::hash;
    use near_indexer_primitives::CryptoHash;
    use std::collections::HashSet;
    use std::fmt::Write;
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    pub struct TestBlock {
        hash: CryptoHash,
        height: u64,
        entropy: BlockEntropy,
        timestamp_nanosec: u64,
        pub(crate) parent: Option<Arc<TestBlock>>,
        tester: Arc<TestBlockMaker>,
        next_fork_seed: AtomicU64,
    }

    pub struct TestBlockMaker {
        root_blocks: Mutex<Vec<Arc<TestBlock>>>,
        final_head: Mutex<Option<Arc<TestBlock>>>,
    }

    impl TestBlock {
        pub fn height(&self) -> u64 {
            self.height
        }

        pub fn last_final_block(self: &TestBlock) -> Option<Arc<TestBlock>> {
            let parent = self.parent.as_ref()?;
            let grandparent = parent.parent.as_ref()?;
            if grandparent.height + 1 == parent.height && parent.height + 1 == self.height {
                return Some(grandparent.clone());
            }
            parent.last_final_block()
        }

        pub fn to_block_view(&self) -> BlockContext {
            let parent_hash = match self.parent.clone() {
                Some(parent) => parent.hash,
                None => {
                    // Invent some parent hash
                    let bytes = self
                        .hash
                        .0
                        .iter()
                        .chain(b"parent")
                        .copied()
                        .collect::<Vec<_>>();
                    hash(&bytes)
                }
            };

            let last_final_block_hash = match self.last_final_block() {
                Some(block) => block.hash,
                None => {
                    // Invent some last final block hash
                    let bytes = self
                        .hash
                        .0
                        .iter()
                        .chain(b"last_final_block")
                        .copied()
                        .collect::<Vec<_>>();
                    hash(&bytes)
                }
            };

            BlockContext {
                hash: self.hash,
                height: self.height.into(),
                entropy: self.entropy.clone(),
                timestamp_nanosec: self.timestamp_nanosec,
                prev_hash: parent_hash,
                last_final_block: last_final_block_hash,
            }
        }

        pub fn child(self: &Arc<TestBlock>) -> Arc<TestBlock> {
            self.descendant(self.height + 1)
        }

        pub fn descendant(self: &Arc<TestBlock>, height: u64) -> Arc<TestBlock> {
            assert!(
                height > self.height,
                "Height must be greater than the parent height"
            );

            let next_fork_seed = self.next_fork_seed.load(Ordering::Relaxed);
            self.next_fork_seed
                .store(next_fork_seed + 1, Ordering::Relaxed);

            let hash_seed = self
                .hash
                .0
                .iter()
                .chain(next_fork_seed.to_be_bytes().iter())
                .copied()
                .collect::<Vec<_>>();
            let block = Arc::new(TestBlock {
                hash: hash(&hash_seed),
                entropy: hash(self.entropy.as_bytes()).into(),
                timestamp_nanosec: self.timestamp_nanosec + 1000000,
                height,
                parent: Some(self.clone()),
                tester: self.tester.clone(),
                next_fork_seed: AtomicU64::new(0),
            });
            *self.tester.final_head.lock().unwrap() = block.last_final_block();
            block
        }
    }

    impl TestBlockMaker {
        pub fn new() -> Arc<Self> {
            Self {
                root_blocks: Mutex::new(Vec::new()),
                final_head: Mutex::new(None),
            }
            .into()
        }

        pub fn block(self: &Arc<Self>, height: u64) -> Arc<TestBlock> {
            let hash_seed: Vec<u8> = b"root"
                .iter()
                .chain(self.root_blocks.lock().unwrap().len().to_be_bytes().iter())
                .copied()
                .collect();
            let mut entropy_seed = hash_seed.clone();
            entropy_seed.extend_from_slice(b"entropy");
            let block = Arc::new(TestBlock {
                hash: hash(&hash_seed),
                entropy: hash(&entropy_seed).into(),
                timestamp_nanosec: 42,
                height,
                parent: None,
                tester: self.clone(),
                next_fork_seed: AtomicU64::new(0),
            });
            self.root_blocks.lock().unwrap().push(block.clone());
            block
        }
    }

    pub struct Tester {
        maker: Arc<TestBlockMaker>,
        tracker: RecentBlocksTracker,
        parents_of_added_blocks: HashSet<CryptoHash>,
        /// When adding a block to the tracker via [`Tester::add`], we debug-print the tracker and
        /// append the output to [`Tester::evolution`]. This allows us to inspect how adding a block
        /// influences finality and canonical status of tracked blocks.
        /// The resulting string can be compared against snapshots, allowing the unittests to catch
        /// regressions.
        evolution: String,
    }

    impl From<u8> for BlockStatus {
        fn from(v: u8) -> BlockStatus {
            match v {
                0 => BlockStatus::OptimisticButNotCanonical,
                1 => BlockStatus::OptimisticAndCanonical,
                2 => BlockStatus::Final,
                _ => unreachable!("unexpected block status"),
            }
        }
    }

    impl Tester {
        pub fn new(heights_to_keep: u64) -> Self {
            let maker = TestBlockMaker::new();
            let tracker = RecentBlocksTracker::new(heights_to_keep);
            Self {
                maker,
                tracker,
                parents_of_added_blocks: HashSet::new(),
                evolution: String::new(),
            }
        }

        pub fn block(&self, height: u64) -> Arc<TestBlock> {
            self.maker.block(height)
        }

        pub fn check(&self, handle: &BlockStatusHandle) -> Option<BlockStatus> {
            handle
                .0
                .upgrade()
                .map(|s| BlockStatus::from(s.0.load(Ordering::Relaxed)))
        }

        pub fn add(&mut self, block: &Arc<TestBlock>) -> BlockStatusHandle {
            assert!(
                !self.parents_of_added_blocks.contains(&block.hash),
                "Cannot retroactively add the parent of an already added block"
            );
            let result = self.tracker.add_block(&block.to_block_view());
            if let Some(parent) = block.parent.clone() {
                self.parents_of_added_blocks.insert(parent.hash);
            }
            let hash = block.hash.to_string();
            writeln!(
                self.evolution,
                "--- after add({}) ---\n{:?}",
                &hash[..7],
                self.tracker
            )
            .unwrap();
            result.block_status
        }
    }

    #[test]
    fn test_no_forks() {
        let mut tester = Tester::new(4);
        let b10 = tester.block(10);
        let b11 = b10.child();
        let b12 = b11.child();
        let b13 = b12.child();
        let b14 = b13.child();
        let b15 = b14.child();

        tester.add(&b11);
        tester.add(&b12);
        tester.add(&b13);
        tester.add(&b14);
        tester.add(&b15);

        insta::assert_snapshot!(tester.evolution);
    }

    #[test]
    fn test_simple_forks() {
        let mut t = Tester::new(5);
        let b10 = t.block(10);
        let b11 = b10.child();
        let b12 = b11.child();
        // Start forks (last final block is 11)
        // fork one:
        let b13 = b12.child();
        // fork two:
        let b14 = b12.descendant(14);
        let b15 = b13.descendant(15);
        // fork three:
        let b16 = b12.descendant(16);

        t.add(&b11);
        t.add(&b12);
        t.add(&b13);
        t.add(&b14);
        t.add(&b16);
        t.add(&b15);

        let b18 = b14.descendant(18);
        t.add(&b18);

        let b19 = b18.child();
        let b20 = b19.child();
        t.add(&b19);
        t.add(&b20);

        insta::assert_snapshot!(t.evolution);
    }

    #[test]
    fn test_complex_forks() {
        let mut t = Tester::new(5);
        let b = t.block(2);
        let b0 = b.descendant(4);
        let b00 = b0.descendant(6);
        let b000 = b00.descendant(8);
        let b001 = b00.descendant(9);
        let b01 = b0.descendant(7);
        let b010 = b01.descendant(9);
        let b011 = b01.descendant(10);
        let b1 = b.descendant(5);
        let b10 = b1.descendant(6);
        let b100 = b10.descendant(8);
        let b101 = b10.descendant(8);
        let b11 = b1.descendant(7);
        let b110 = b11.descendant(9);
        let b111 = b11.descendant(10);

        t.add(&b0);
        t.add(&b00);
        t.add(&b000);
        t.add(&b001);
        t.add(&b01);
        t.add(&b010);
        t.add(&b011);
        t.add(&b1);
        t.add(&b10);
        t.add(&b100);
        t.add(&b101);
        t.add(&b11);
        t.add(&b110);
        t.add(&b111);

        //    Recent blocks: (Window = 6 to 10, GC limit 0)
        //    ├─[4] C   F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA "b0"
        //    │ ├─[6]     7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "b00"
        //    │ │ ├─[8]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "b000"
        //    │ │ └─[9]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "b001"
        //    │ └─[7] C   8FoDbEfMuYmtr7SXRPiscHR4mQ6m5nCyuca43eAopktY "b01"
        //    │   ├─[9]     8jRJjsyqjoAbyWbjLXTjFNiKTwT8s4xspouvRaZGfh6R "b010"
        // CH │   └─[10] C   CnbxNBi2SVDZo9z8V8kwrmE3pUkozpDvpCCg9Tq25rY3 "b011"
        //    └─[5]     FsmQgeGtsztQh7aaRtaj59JToK91VqiRyRqXXRN85ZAA "b1"
        //      ├─[6]     6s7VNQLN9b4SpwUdEq8LqKwBjf8SqUuutACcMtHwULu8 "b10"
        //      │ ├─[8]     GounuZUfMmxdVequL65iUm7D94sKYg67Q34Z5cjRjZ71 "b100"
        //      │ └─[8]     7aXqE7cPZt6FnVcpytqW3oy5y2E17X9Gpgs6C7praap5 "b101"
        //      └─[7]     2xhND7PwiNZckwCnXFa25wMG1G8JWfKN2Sinmbz3W6xK "b11"
        //        ├─[9]     6E2vqjZLbuUY2y6VK571Ai3pk43EUHXuNxibJuBGh44T "b110"
        //        └─[10]     Cq9uMZqNZr6zuF7nT6yfGms1ptaVVu5dAdiRJ6pqCTN8 "b111"

        // Now, we test some pathological cases where the data being given is not consistent
        // with Near blockchain's behavior. Still, we want reasonable behavior and no crashes.
        let b102 = b10.descendant(7);
        let b1020 = b102.descendant(8);
        t.add(&b102);
        t.add(&b1020);
        //    Recent blocks: (Window = 6 to 10, GC limit 6)
        // FH └─[6] C F 6s7VNQLN9b4SpwUdEq8LqKwBjf8SqUuutACcMtHwULu8 "b10"
        // CH   ├─[8] C   GounuZUfMmxdVequL65iUm7D94sKYg67Q34Z5cjRjZ71 "b100"
        //      ├─[8]     7aXqE7cPZt6FnVcpytqW3oy5y2E17X9Gpgs6C7praap5 "b101"
        //      └─[7]     FK5PX18pxwwtaB6AvYjNkWZ4Jvnn2HeNx4tknkM5g7VP "b102"
        //        [8]     AQif6GckVVDt4L4rUeAN43PNComjsa7fPYAF5NHW7oX8 "b1020"

        let b10200 = b1020.descendant(11);
        let b102000 = b10200.descendant(12);
        let b1020000 = b102000.descendant(13);
        t.add(&b10200);
        t.add(&b102000);
        t.add(&b1020000);

        //    Recent blocks: (Window = 9 to 13, GC limit 9)
        // FH └─[11] C F NW4CWxr6ptWa9tsV2gMhGPdE7ecNWfCrnJDfJwx9yv9 "b10200"
        //      [12] C   4Vwtcagaq6fi5j82suG4j8HiaU3SMbqotrZzT3bjqwcP "b102000"
        // CH   [13] C   GktyudcCf3dBkWCdjq9dFssY7KZRRZQJ1TZH3ZMw8LWk "b1020000"
        insta::assert_snapshot!(t.evolution);
    }

    #[test]
    #[expect(non_snake_case)]
    fn prune_old_blocks__should_drop_connected_pruned_block_nodes() {
        // Given a tree where finality is stalled by a height gap (b3 is skipped),
        // so b1 and b2 sit in the tracker without any finality advancement.
        // The first finality event will jump straight to b4, pruning b1 and b2
        // together in a single prune_old_blocks call.
        let mut tester = Tester::new(2);
        let b1 = tester.block(1);
        let b2 = b1.child(); // h=2
        let b4 = b2.descendant(4); // h=4, parent=b2 (h=3 intentionally skipped)
        let b5 = b4.child(); // h=5
        let b6 = b5.child(); // h=6 → first block whose grandparent-parent-self
        // forms 3 consecutive heights (b4-b5-b6), so its
        // last_final_block is b4

        tester.add(&b1);
        tester.add(&b2);
        tester.add(&b4);
        tester.add(&b5);

        // Capture Weak refs to b1 and b2 while they are still in the tree.
        // After add(b6), final_head will jump from None to b4 (h=4), and
        // prune_old_blocks will evict both b1 (h=1) and b2 (h=2) in one call.
        // b1 and b2 are connected by the parent<->children Arc cycle:
        //   b1.children = [Arc(b2)]
        //   b2.parent   = Some(Arc(b1))
        // Without breaking the cycle, neither can be freed.
        let weak_b1 = Arc::downgrade(
            tester
                .tracker
                .hash_to_node
                .get(&b1.hash)
                .expect("b1 present before prune"),
        );
        let weak_b2 = Arc::downgrade(
            tester
                .tracker
                .hash_to_node
                .get(&b2.hash)
                .expect("b2 present before prune"),
        );

        // When the finality jump triggers a multi-node prune
        tester.add(&b6);

        // Then both pruned BlockNodes are dropped (cycle was broken)
        assert!(
            weak_b1.upgrade().is_none(),
            "pruned BlockNode b1 leaked — parent<->children Arc cycle not broken"
        );
        assert!(
            weak_b2.upgrade().is_none(),
            "pruned BlockNode b2 leaked — parent<->children Arc cycle not broken"
        );
    }

    /// Tests that a subtree that won't be included (b3_fork) is removed, even if that subtree is a
    /// descendant of a block that is included and recent (b2, F)
    /// ```text
    ///   (b1, F)
    ///    │
    /// ═══════════════════════ ← cutoff (h ≥ 2). Remove blocks older than this.
    ///    │
    ///   (b2, F)               ← new root
    ///    ├──────────┐
    ///   (b3, F)  (b3_fork)    ← b3_fork subtree should be pruned
    ///    │          │
    ///   (b4)     (b4_fork)    ← should be pruned as part of b3_fork prune
    ///    │
    ///   (b5)                  ← This block makes 3F final.
    /// ```
    #[test]
    #[expect(non_snake_case)]
    fn prune_old_blocks__should_drop_dead_fork_descendants_of_kept_nodes() {
        let mut tester = Tester::new(4);
        let b1 = tester.block(1);
        let b2 = b1.child();
        let b3 = b2.child();
        let b4 = b3.child();
        let b5 = b4.child();
        let b3_fork = b2.descendant(3);
        let b4_fork = b3_fork.child();

        // Given: a fork
        // (b1, F)
        //    │
        // (b2, F)
        //    ├──────────┐
        //   (b3)     (b3_fork)
        //    │         │
        //   (b4)     (b4_fork)
        tester.add(&b1);
        tester.add(&b2);
        tester.add(&b3);
        tester.add(&b3_fork);
        tester.add(&b4);
        tester.add(&b4_fork);

        let weak_b3_fork = Arc::downgrade(
            tester
                .tracker
                .hash_to_node
                .get(&b3_fork.hash)
                .expect("b3_fork present before prune"),
        );
        let weak_b4_fork = Arc::downgrade(
            tester
                .tracker
                .hash_to_node
                .get(&b4_fork.hash)
                .expect("b4_fork present before prune"),
        );

        // When: b5 is added, advancing final_head to b3
        //   (b1, F)
        //    │
        // ═══════════════════════ ← cutoff (h ≥ 2). Remove blocks older than this.
        //    │
        //   (b2, F)               ← new root
        //    ├──────────┐
        //   (b3, F)  (b3_fork)    ← b3_fork subtree should be pruned
        //    │          │
        //   (b4)     (b4_fork)    ← should be pruned as part of b3_fork prune
        //    │
        //   (b5)                  ← This block makes 3F final.
        tester.add(&b5);

        // Then: We expect b3_fork subtree to be pruned and b2 to become the new root
        //   (b2, F)               ← new root
        //    │
        //   (b3, F)
        //    │
        //   (b4)
        //    │
        //   (b5)
        insta::assert_snapshot!(tester.evolution);
        // And the dead-fork BlockNodes were fully freed (not just detached from hash_to_node).
        assert!(
            weak_b3_fork.upgrade().is_none(),
            "dead-fork BlockNode b3_fork leaked — prune_dead_children did not detach"
        );
        assert!(
            weak_b4_fork.upgrade().is_none(),
            "dead-fork BlockNode b4_fork leaked — descendant of detached dead-fork not freed"
        );
    }

    /// Tests that `minimum_height_to_keep` returns `Some` in case we have a final block height.
    /// This is a test to protect against regressions: We only run the cleanup loop in case
    /// `minimum_height_to_keep` returns Some.
    #[test]
    #[expect(non_snake_case)]
    fn minimum_height_to_keep__should_return_some_if_final_block_exists() {
        let mut tester = Tester::new(4);
        let b1 = tester.block(1);
        let b2 = b1.child();
        let b3 = b2.child();
        tester.add(&b1);
        tester.add(&b2);
        tester.add(&b3);
        assert_eq!(tester.tracker.minimum_height_to_keep(), Some(1.into()))
    }

    #[test]
    #[expect(non_snake_case)]
    fn atomic_block_status__should_not_downgrade_from_final() {
        // Given
        let s = AtomicBlockStatus(AtomicU8::new(BlockStatus::Final.into()));

        // When / Then
        s.make_canonical();
        assert!(s.is_final());
        s.make_non_canonical();
        assert!(s.is_final());
    }

    #[test]
    #[expect(non_snake_case)]
    fn block_status_handle__should_observe_same_atomic_as_tracker() {
        // Regression guard: the `BlockStatusHandle` returned by `Tester::add`
        // must observe the same atomic the tracker mutates on the BlockNode.
        // A refactor that wires the returned handle to a separate Arc would
        // silently break finality observation for QueuedRequest. We exercise
        // all four outcomes through the returned handle:
        //  - OptimisticAndCanonical (canonical-head update on add),
        //  - OptimisticButNotCanonical (sibling root losing canonical race),
        //  - Final (last_final_block advance during a 3-block chain),
        //  - None (BlockNode dropped by window-prune).
        let mut tester = Tester::new(3);
        let b1 = tester.block(1);
        let b1_fork = tester.block(1); // distinct root at the same height
        let b2 = b1.child();
        let b3 = b2.child();
        let b4 = b3.child();
        let b5 = b4.child();

        let s1 = tester.add(&b1);
        // b1 is the only block → canonical head → OptimisticAndCanonical.
        assert_eq!(tester.check(&s1), Some(BlockStatus::OptimisticAndCanonical));

        let s1_fork = tester.add(&b1_fork);
        // b1 already holds canonical at this height; b1_fork loses the race.
        assert_eq!(
            tester.check(&s1_fork),
            Some(BlockStatus::OptimisticButNotCanonical)
        );

        tester.add(&b2);
        tester.add(&b3);
        // add(b3) advances last_final_block to b1 (3 consecutive heights b1-b2-b3),
        // promoting b1 to Final. The handle from add(b1) must observe this.
        assert_eq!(tester.check(&s1), Some(BlockStatus::Final));

        tester.add(&b4);
        tester.add(&b5);
        // After add(b5): max=5, window=3, final_head=b3 (h=3), min_keep=3.
        // b1 (h=1) falls below the recency window → BlockNode dropped → handle
        // can no longer observe the status.
        assert_eq!(tester.check(&s1), None);
    }
}
