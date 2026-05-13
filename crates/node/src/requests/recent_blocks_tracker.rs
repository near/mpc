use derive_more::Into;
use near_indexer_primitives::types::BlockHeight;
use near_indexer_primitives::CryptoHash;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Add;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Tracks the topology of the recent blocks, using the blocks given by the indexer.
///
/// This class provides two important functionalities:
///  - Converts a stream of optimistic blocks from the indexer into a stream of finalized
///    blocks. The content of each block in the finalized stream is specified via the `T`
///    type parameter.
///  - For each block added via `add_block`, it returns a `Weak<AtomicBlockStatus>` that can be
///    used to observe that block's current `BlockStatus`.
///
/// We have certain expectations of the order of blocks that come from the indexer.
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
/// Note: The use of Arc is a little unfortunate. Logically we only need Rc, but this code needs
/// to work in futures, and Rc is not Send. So we use Arc instead.
pub struct RecentBlocksTracker<T: Clone + 'static> {
    window_size: u64,
    /// By "root", we mean the blocks whose parents we don't know or are older than the window.
    /// The children of the root are the earliest blocks we are keeping who do not have any order
    /// with each other.
    root_children: Vec<Arc<BlockNode>>,
    /// The head of the canonical chain. This is the chain of the highest-height block we've seen.
    /// This may be None if we have no block at all.
    canonical_head: Option<Arc<BlockNode>>,
    /// The head of the final chain. This is determined by recovering information from the
    /// last_final_block fields of the block headers given to us. This may be None if we have not
    /// seen any final blocks yet.
    final_head: Option<Arc<BlockNode>>,
    /// The maximum height of any block we have been given via `add_block`.
    maximum_height_available: BlockHeight,
    /// Maps block hashes to their nodes in the tree.
    hash_to_node: HashMap<CryptoHash, Arc<BlockNode>>,
    /// Maps block hashes to their content; this is to provide the stream of finalized blocks.
    /// Technically, instead of a hashmap we could put this in the node, but that would clutter
    /// the code by requiring the T type parameter everywhere.
    node_to_content: HashMap<CryptoHash, T>,
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

pub struct AtomicBlockStatus(AtomicU8);

impl AtomicBlockStatus {
    pub fn is_final(&self) -> bool {
        self.0.load(Ordering::Relaxed) == u8::from(BlockStatus::Final)
    }

    pub fn is_canonical(&self) -> bool {
        let status = self.0.load(Ordering::Relaxed);
        status == u8::from(BlockStatus::OptimisticAndCanonical)
            || status == u8::from(BlockStatus::Final)
    }

    fn make_final(&self) {
        self.0.store(BlockStatus::Final.into(), Ordering::Relaxed);
    }

    fn make_canonical(&self) {
        if self.is_final() {
            tracing::error!("received invalid data from indexer. Downgrading from final to canonical is not possible");
            return;
        }
        self.0.store(
            BlockStatus::OptimisticAndCanonical.into(),
            Ordering::Relaxed,
        );
    }

    fn make_non_canonical(&self) {
        if self.is_final() {
            tracing::error!("received invalid data from indexer. Downgrading from final to non-canonical is not possible");
            return;
        }
        self.0.store(
            BlockStatus::OptimisticButNotCanonical.into(),
            Ordering::Relaxed,
        );
    }
}

pub struct AddBlockResult<T> {
    /// The list of newly finalized blocks, in ascending height order. Each entry is a tuple of
    /// the block height and the data passed to us when adding the block.
    /// It is guaranteed that the new final blocks returned from multiple calls to add_block are
    /// contiguous, thus forming the stream of finalized blocks.
    pub new_final_blocks: Vec<(u64, T)>,
    pub block_ref: Weak<AtomicBlockStatus>,
}

/// Represents a block in the recent blockchain.
struct BlockNode {
    hash: CryptoHash,
    height: u64,
    /// Indicates the finality status of this block. Held as `Arc` so that a `Weak` reference
    /// can be handed out (via `AddBlockResult::block_ref`) to consumers like `QueuedRequest`,
    /// which observe status changes and detect pruning when the upgrade fails.
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
    /// Walk the subtree of this node and identify nodes to prune, as well as nodes that become
    /// orphaned:
    ///  1. **Dead fork** (`!is_final && height ≤ final_head.height`):
    ///     This block is **not** final and it is **older** than the most recent final height.
    ///     This means one of the following must be true:
    ///     1. This block is actually supposed to be final, but for some reason, the indexer
    ///        missed it. For example:
    ///        ```text
    ///              self (N)
    ///                 │
    ///          missed final_block (N+1)
    ///                 │
    ///          Final block (N+2)
    ///        ```
    ///        According to our assumptions about the indexer stream, this is **not** possible:
    ///        > _if A < B and B < C, and both A and C are given, then B must also be given._
    ///        > _In other words there should not be any gaps._
    ///     2. This block sits on a dead fork:
    ///         ```text
    ///                  Common Head
    ///                       /   \
    ///                     ...    ...
    ///                     /       \
    ///              self (N)        \
    ///                  │            \
    ///                (N+1)           \
    ///                /   \       Final block (N+2)
    ///               /     \
    ///            (N+3)     \
    ///                       \
    ///                      (N+4)
    ///         ```
    ///     In this case, we can remove the entire subtree.
    ///
    ///  2. **Outside window** (`height < min_height_to_keep`):
    ///     This block is too old. We drop it and recurse into children.
    ///     ```text
    ///           self (N < min_height_to_keep)
    ///              │
    ///             ...
    ///              │
    ///       ------------------- cutoff height >= min_height_to_keep
    ///              │
    ///             ...
    ///     ```
    ///  3. **In-window and not on a dead fork**:
    ///     We can stop the recursion and append this node `new_roots`.
    ///     ```text
    ///             ...
    ///              │
    ///       ------------------- cutoff height >= min_height_to_keep
    ///              │
    ///       self (N >= min_height_to_keep)
    ///             ...
    ///     ```
    fn partition_subtree(
        &self,
        min_height_to_keep: u64,
        final_head_height: Option<u64>,
        new_roots: &mut Vec<CryptoHash>,
        blocks_to_prune: &mut Vec<CryptoHash>,
    ) {
        if final_head_height.is_some_and(|fh| self.height <= fh) && !self.status.is_final() {
            // This block sits on a dead subtree. It has nothing to contribute.
            // Its children must be removed and we can terminate the recursion.
            self.collect_subtree_hashes(blocks_to_prune);
            return;
        }
        if self.height < min_height_to_keep {
            // This block is too old for us to be useful, we will prune it.
            blocks_to_prune.push(self.hash);
            let children = self.children.lock().expect("lock must not be poisoned");
            for child in children.iter() {
                child.partition_subtree(
                    min_height_to_keep,
                    final_head_height,
                    new_roots,
                    blocks_to_prune,
                );
            }
        } else {
            // This block is right below the cut-off line and will need to be kept.
            // It will become a new root.
            new_roots.push(self.hash);
            // However, its children might sit on dead forks, so we need check for that.
            let Some(fh) = final_head_height else {
                return;
            };
            if self.height < fh {
                self.prune_dead_children(fh, blocks_to_prune);
            }
        }
    }

    /// This block is kept, but it may have descendants that sit on dead forks
    fn prune_dead_children(&self, final_head_height: u64, blocks_to_prune: &mut Vec<CryptoHash>) {
        let mut children = self.children.lock().unwrap();
        children.retain(|child| {
            if child.height <= final_head_height && !child.status.is_final() {
                child.collect_subtree_hashes(blocks_to_prune);
                false
            } else {
                if child.height < final_head_height {
                    child.prune_dead_children(final_head_height, blocks_to_prune);
                }
                true
            }
        });
    }

    /// Walk this subtree and collect every node's hash on it.
    fn collect_subtree_hashes(&self, blocks_to_prune: &mut Vec<CryptoHash>) {
        blocks_to_prune.push(self.hash);
        let children = self.children.lock().expect("lock must not be poisoned");
        for child in children.iter() {
            child.collect_subtree_hashes(blocks_to_prune);
        }
    }

    fn get_parent(&self) -> Option<Arc<BlockNode>> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    fn debug_print(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        indents: &mut Vec<u8>,
        final_head: Option<CryptoHash>,
        canonical_head: Option<CryptoHash>,
        content_printer: &impl Fn(&CryptoHash, &mut std::fmt::Formatter<'_>) -> std::fmt::Result,
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
        content_printer(&self.hash, f)?;
        writeln!(f)?;
        let children = self.children.lock().unwrap();
        for (i, child) in children.iter().enumerate() {
            if children.len() == 1 {
                child.debug_print(f, indents, final_head, canonical_head, content_printer)?;
            } else {
                let indent = if i + 1 == children.len() { 2 } else { 3 };
                indents.push(indent);
                child.debug_print(f, indents, final_head, canonical_head, content_printer)?;
                indents.pop();
            }
        }
        Ok(())
    }
}

#[derive(Clone, Into)]
pub struct BlockEntropy([u8; 32]);

impl BlockEntropy {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<CryptoHash> for BlockEntropy {
    fn from(value: CryptoHash) -> Self {
        BlockEntropy(value.into())
    }
}

/// A view of a block that is sufficient for the RecentBlocksTracker.
#[derive(Clone)]
pub struct BlockViewLite {
    pub hash: CryptoHash,
    pub height: u64,
    pub prev_hash: CryptoHash,
    pub last_final_block: CryptoHash,
    pub entropy: BlockEntropy,
    pub timestamp_nanosec: u64,
}

impl<T: Clone + Debug> RecentBlocksTracker<T> {
    pub fn new(window_size: u64) -> Self {
        Self {
            window_size,
            root_children: Vec::new(),
            canonical_head: None,
            final_head: None,
            maximum_height_available: 0,
            hash_to_node: HashMap::new(),
            node_to_content: HashMap::new(),
        }
    }

    /// Adds a block to the tracker. This is expected to be called for EVERY block given by the
    /// indexer (whether or not it is interesting). The content is whatever content that we want
    /// to buffer for the stream of final blocks.
    pub fn add_block(
        &mut self,
        block: &BlockViewLite,
        content: T,
    ) -> anyhow::Result<AddBlockResult<T>> {
        if self.hash_to_node.contains_key(&block.hash) {
            anyhow::bail!("Block already exists in the tracker");
        }
        let status = Arc::new(AtomicBlockStatus(AtomicU8::new(u8::from(
            BlockStatus::OptimisticButNotCanonical,
        ))));
        let block_ref = Arc::downgrade(&status);
        let parent = self.hash_to_node.get(&block.prev_hash).cloned();
        let node = Arc::new(BlockNode {
            hash: block.hash,
            height: block.height,
            status,
            parent: parent.as_ref().map(Arc::downgrade),
            children: Mutex::new(Vec::new()),
        });
        self.hash_to_node.insert(block.hash, node.clone());
        self.node_to_content.insert(block.hash, content);
        if let Some(parent) = parent {
            parent.children.lock().unwrap().push(node.clone());
        } else {
            self.root_children.push(node.clone());
        }

        let new_final_blocks = self.maybe_update_final_head(block.last_final_block);
        // We must do this lookup before calling prune_old_blocks or else we may no longer have
        // some of the blocks. Note: filter_map should not really filter anything out, but we're
        // doing this defensively to not crash just in case we have a bug.
        let new_final_blocks = new_final_blocks
            .into_iter()
            .filter_map(|node| Some((node.height, self.node_to_content.get(&node.hash)?.clone())))
            .collect();
        match self.canonical_head.as_ref() {
            None => {
                self.update_canonical_head(&node);
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
        Ok(AddBlockResult {
            new_final_blocks,
            block_ref,
        })
    }

    /// Update the final head if the new final head received from a block is newer.
    /// Returns the list of newly finalized blocks in increasing height order.
    fn maybe_update_final_head(&mut self, potential_final_head: CryptoHash) -> Vec<Arc<BlockNode>> {
        let final_head_node = self.hash_to_node.get(&potential_final_head);
        let mut new_final_blocks = Vec::new();
        if let Some(final_head_node) = final_head_node {
            let mut node = final_head_node.clone();
            loop {
                if node.status.is_final() {
                    break;
                }
                node.status.make_final();
                new_final_blocks.push(node.clone());
                let Some(parent) = node.get_parent() else {
                    break;
                };
                node = parent;
            }
            if self
                .final_head
                .as_ref()
                .is_none_or(|prev_final_head| prev_final_head.height < final_head_node.height)
            {
                self.final_head = Some(final_head_node.clone());
            }
        }
        new_final_blocks.reverse();
        new_final_blocks
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

        let mut old_node = self.canonical_head.clone();
        while let Some(current_node) = old_node {
            if let Some(common_ancestor) = &common_ancestor {
                if Arc::ptr_eq(&current_node, common_ancestor) {
                    break;
                }
            }
            current_node.status.make_non_canonical();
            old_node = current_node.get_parent();
        }
        self.canonical_head = Some(new_canonical_head.clone());
    }

    /// Calculates the minimum height of blocks that we need to keep.
    /// This is typically canonical_head.height - window_size + 1, but in case of delayed finality,
    /// we ensure that the final head is not pruned. Otherwise, not only would the logic be very
    /// messy, but also we would not be able to provide a contiguous stream of finalized blocks.
    fn minimum_height_to_keep(&self) -> Option<u64> {
        let Some(final_head) = &self.final_head else {
            return None;
        };
        Some(
            self.maximum_height_available
                .saturating_sub(self.window_size)
                .add(1)
                .min(final_head.height),
        )
    }

    /// Remove blocks that are no longer needed:
    ///  - **Recency Window prune:** Drop nodes below `minimum_height_to_keep`,
    ///    their children become new roots
    ///  - **Dead-fork prune.** Drop non-final nodes at heights ≤
    ///    `final_head.height` along with their entire subtree (a descendant
    ///    of a dead fork can never become final, by the BFT-finality safety
    ///    theorem).
    ///
    /// **Example:**
    /// If block 8 is finalized, we can remove the subtrees at (5), (6) and (7):
    ///
    /// ```text
    ///  ---------------------------┐
    ///     These blocks will       ┆
    ///     never be included       ┆
    ///                             ┆
    ///                             ┆
    ///   root 1   root 2           ┆ root 3
    ///   (1)                       ┆              Dead-fork prune at (1)
    ///    │        (2)             ┆              Dead-fork prune at (2)
    ///   (3)        │              ┆
    ///    │         │              ┆ (4F)         Recency window prune node (4F)
    ///  ┌─┴─┐       │       ┌──────────┴─┐
    /// ════════════════════════════════════════ ← cutoff (h ≥ 4). Remove blocks older than this.
    /// (5)  │       │       │      ┆     │
    ///  │   │       │       │      ┆    (7F)      (7F) becomes new root
    ///  │   │       │       │   ┌────────┴─┐
    ///  │  (6)      │       │   │  ┆       │
    ///  │   │       │       │  (8) ┆       │      Dead-fork prune at (8)
    ///  │   │       │       │   │  ┆     (9F)
    ///  │   │       │      (10) │  ┆       │      Dead-fork prune at (10)
    ///  │   │       │       │   │  ┆     (11F)    ← latest final block height.
    ///  │   │       │       │   │  ┆       │         Remove subtrees of older,
    ///  │   │       │       │   │  ┆       │         non-final blocks
    ///  │   │       │       │   │  ┆       │
    ///  │   │       │       │   │  ┆     (12)
    ///  │   │       │      (13) │  ┆       │
    ///  │   │       │       │   │  ┆       │
    ///  ..  ..      ..      ..  .. ┆       ..
    ///
    /// ```
    /// After prune, we have one new root:
    /// ```text
    ///  root 1
    ///   (7F)
    ///    │
    ///    ..
    ///             ..
    ///  ```
    fn prune_old_blocks(&mut self) {
        let Some(min_height_to_keep) = self.minimum_height_to_keep() else {
            return;
        };
        let final_head_height = self.final_head.as_ref().map(|n| n.height);

        let mut new_roots = Vec::new();
        let mut blocks_to_prune = Vec::new();

        for root in self.root_children.iter() {
            root.partition_subtree(
                min_height_to_keep,
                final_head_height,
                &mut new_roots,
                &mut blocks_to_prune,
            );
        }

        self.root_children = new_roots
            .iter()
            .filter_map(|hash| {
                self.hash_to_node.get(hash).cloned().or_else(|| {
                    // note: this should NEVER happen. Right now, it's a guaranteed dead code path.
                    // However, to protect against future refactors of `partition_subtree`, or some
                    // odd behavior, we simply print an error. Missing a root child is not something
                    // that requires us to crash the node.
                    tracing::error!(
                        "Error: missing node for root hash {:?}. RecentBlocksTracker: {:?}",
                        hash,
                        self
                    );
                    None
                })
            })
            .collect();

        for hash in blocks_to_prune {
            self.hash_to_node.remove(&hash);
            self.node_to_content.remove(&hash);
        }
    }
}

impl<T: Clone + Debug> Debug for RecentBlocksTracker<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "   Recent blocks: (Window = {} to {}, GC limit {})",
            self.maximum_height_available
                .saturating_sub(self.window_size)
                .add(1),
            self.maximum_height_available,
            self.minimum_height_to_keep().unwrap_or(0)
        )?;
        let final_head = self.final_head.as_ref().map(|n| n.hash);
        let canonical_head = self.canonical_head.as_ref().map(|n| n.hash);

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
                &|hash, f| {
                    if let Some(content) = self.node_to_content.get(hash) {
                        write!(f, "{:?}", content)
                    } else {
                        write!(f, "")
                    }
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::{BlockEntropy, BlockStatus, BlockViewLite, RecentBlocksTracker};
    use near_indexer::near_primitives::hash::hash;
    use near_indexer_primitives::CryptoHash;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};
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

        pub fn to_block_view(&self) -> BlockViewLite {
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

            BlockViewLite {
                hash: self.hash,
                height: self.height,
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
        tracker: RecentBlocksTracker<String>,
        parents_of_added_blocks: HashSet<CryptoHash>,
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
            }
        }

        pub fn block(&self, height: u64) -> Arc<TestBlock> {
            self.maker.block(height)
        }

        pub fn check(&self, block: &Arc<TestBlock>) -> Option<BlockStatus> {
            self.tracker
                .hash_to_node
                .get(&block.hash)
                .map(|node| BlockStatus::from(node.status.0.load(Ordering::Relaxed)))
        }

        pub fn add(&mut self, block: &Arc<TestBlock>, name: &str) -> String {
            assert!(
                !self.parents_of_added_blocks.contains(&block.hash),
                "Cannot retroactively add the parent of an already added block"
            );
            let result = self
                .tracker
                .add_block(&block.to_block_view(), name.to_string())
                .unwrap();
            if let Some(parent) = block.parent.clone() {
                self.parents_of_added_blocks.insert(parent.hash);
            }
            result
                .new_final_blocks
                .iter()
                .map(|(_, name)| name.clone())
                .collect::<Vec<_>>()
                .join(",")
        }

        pub fn print(&self) {
            println!("{:?}", self.tracker);
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
        let b16 = b15.child();

        assert_eq!(&tester.add(&b11, "11"), "");
        assert_eq!(&tester.add(&b12, "12"), "");
        assert_eq!(&tester.add(&b13, "13"), "11");
        assert_eq!(&tester.add(&b14, "14"), "12");
        assert_eq!(&tester.add(&b15, "15"), "13");
        //    Recent blocks: (Window = 12 to 15, GC limit 12)
        //    └─[12] C F 7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "12"
        // FH   [13] C F DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "13"
        //      [14] C   4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA "14"
        // CH   [15] C   7inNzFR4mz4TRu9CSajNQnWxwhKDcYzTYubtM6zFri7Y "15"
        tester.print();

        // At this point, the tracker should keep blocks 12, 13, 14, 15.
        assert_eq!(tester.check(&b10), None);
        assert_eq!(tester.check(&b11), None);
        assert_eq!(tester.check(&b12), Some(BlockStatus::Final));
        assert_eq!(tester.check(&b13), Some(BlockStatus::Final));
        assert_eq!(
            tester.check(&b14),
            Some(BlockStatus::OptimisticAndCanonical)
        );
        assert_eq!(
            tester.check(&b15),
            Some(BlockStatus::OptimisticAndCanonical)
        );
        assert_eq!(tester.check(&b16), None);
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
        let b17 = b13.descendant(17);

        assert_eq!(&t.add(&b11, "11"), "");
        assert_eq!(&t.add(&b12, "12"), "");
        assert_eq!(&t.add(&b13, "13"), "11");
        assert_eq!(&t.add(&b14, "14"), "");
        assert_eq!(&t.add(&b16, "16"), "");
        assert_eq!(&t.add(&b15, "15"), "");

        //    Recent blocks: (Window = 12 to 16, GC limit 11)
        // FH └─[11] C F F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA "11"
        //      [12] C   7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "12"
        //      ├─[13]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "13"
        //      │ [15]     4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA "15"
        //      ├─[14]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "14"
        // CH   └─[16] C   81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG "16"
        t.print();

        // This block has been removed by the tracker
        assert_eq!(t.check(&b10), None);
        // The tracker kept the block internally as it is the last final block, but it is still
        // outside of the window.
        assert_eq!(t.check(&b11), Some(BlockStatus::Final));
        assert_eq!(t.check(&b12), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(t.check(&b13), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b14), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b15), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b16), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(t.check(&b17), None);

        let b18 = b14.descendant(18);
        assert_eq!(&t.add(&b18, "18"), "");
        //    Recent blocks: (Window = 14 to 18, GC limit 11)
        // FH └─[11] C F F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA "11"
        //      [12] C   7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "12"
        //      ├─[13]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "13"
        //      │ [15]     4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA "15"
        //      ├─[14] C   DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "14"
        // CH   │ [18] C   GHjy91467tR3nyE2ycq9JM4MH22ZoBZCrkXSEFnT7Vhp "18"
        //      └─[16]     81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG "16"
        t.print();

        assert_eq!(t.check(&b13), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b14), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(t.check(&b16), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b18), Some(BlockStatus::OptimisticAndCanonical));

        let b19 = b18.child();
        let b20 = b19.child();
        assert_eq!(&t.add(&b19, "19"), "");
        assert_eq!(&t.add(&b20, "20"), "12,14,18");

        //    Recent blocks: (Window = 16 to 20, GC limit 16)
        // FH ├─[18] C F GHjy91467tR3nyE2ycq9JM4MH22ZoBZCrkXSEFnT7Vhp "18"
        //    │ [19] C   DtoqtibWnNxpvqwgXUXDMrawHNQPP2AC8p3fjdiZvtKg "19"
        // CH │ [20] C   24aEbuUrHRACVS8Ty27pbWnBygML7QBttQo44trWLen7 "20"
        //    └─[16]     81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG "16"
        t.print();

        // b14, b15 were pruned (too old, newer final blocks).
        // b16 and the b13/b15 subtree were discarded when b18 became final
        // (dead-fork drop on finality advance).
        assert_eq!(t.check(&b14), None);
        assert_eq!(t.check(&b15), None);
        assert_eq!(t.check(&b16), None);
        assert_eq!(t.check(&b17), None);
        assert_eq!(t.check(&b18), Some(BlockStatus::Final));
        assert_eq!(t.check(&b19), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(t.check(&b20), Some(BlockStatus::OptimisticAndCanonical));
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

        assert_eq!(&t.add(&b0, "b0"), "");
        assert_eq!(&t.add(&b00, "b00"), "");
        assert_eq!(&t.add(&b000, "b000"), "");
        assert_eq!(&t.add(&b001, "b001"), "");
        assert_eq!(&t.add(&b01, "b01"), "");
        assert_eq!(&t.add(&b010, "b010"), "");
        assert_eq!(&t.add(&b011, "b011"), "");
        assert_eq!(&t.add(&b1, "b1"), "");
        assert_eq!(&t.add(&b10, "b10"), "");
        assert_eq!(&t.add(&b100, "b100"), "");
        assert_eq!(&t.add(&b101, "b101"), "");
        assert_eq!(&t.add(&b11, "b11"), "");
        assert_eq!(&t.add(&b110, "b110"), "");
        assert_eq!(&t.add(&b111, "b111"), "");

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
        t.print();
        assert_eq!(t.check(&b0), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(t.check(&b00), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b000), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b01), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(t.check(&b010), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b011), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(t.check(&b1), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b10), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b100), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b11), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b110), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b111), Some(BlockStatus::OptimisticButNotCanonical));

        // Now, we test some pathological cases where the data being given is not consistent
        // with Near blockchain's behavior. Still, we want reasonable behavior and no crashes.
        let b102 = b10.descendant(7);
        let b1020 = b102.descendant(8);
        assert_eq!(t.add(&b102, "b102"), "b1");
        assert_eq!(t.add(&b1020, "b1020"), "b10");
        //    Recent blocks: (Window = 6 to 10, GC limit 6)
        //    ├─[6]     7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "b00"
        //    │ ├─[8]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "b000"
        //    │ └─[9]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "b001"
        //    ├─[7] C   8FoDbEfMuYmtr7SXRPiscHR4mQ6m5nCyuca43eAopktY "b01"
        //    │ ├─[9]     8jRJjsyqjoAbyWbjLXTjFNiKTwT8s4xspouvRaZGfh6R "b010"
        // CH │ └─[10] C   CnbxNBi2SVDZo9z8V8kwrmE3pUkozpDvpCCg9Tq25rY3 "b011"
        // FH ├─[6] C F 6s7VNQLN9b4SpwUdEq8LqKwBjf8SqUuutACcMtHwULu8 "b10"
        //    │ ├─[8]     GounuZUfMmxdVequL65iUm7D94sKYg67Q34Z5cjRjZ71 "b100"
        //    │ ├─[8]     7aXqE7cPZt6FnVcpytqW3oy5y2E17X9Gpgs6C7praap5 "b101"
        //    │ └─[7]     FK5PX18pxwwtaB6AvYjNkWZ4Jvnn2HeNx4tknkM5g7VP "b102"
        //    │   [8]     AQif6GckVVDt4L4rUeAN43PNComjsa7fPYAF5NHW7oX8 "b1020"
        //    └─[7]     2xhND7PwiNZckwCnXFa25wMG1G8JWfKN2Sinmbz3W6xK "b11"
        //      ├─[9]     6E2vqjZLbuUY2y6VK571Ai3pk43EUHXuNxibJuBGh44T "b110"
        //      └─[10]     Cq9uMZqNZr6zuF7nT6yfGms1ptaVVu5dAdiRJ6pqCTN8 "b111"
        //
        // Note above: the canonical head is not a descendant of final head. This can't happen in
        // the real blockchain, but here we fed in a pathological scenario.
        t.print();
        // b0 was removed (older than recent window).
        assert_eq!(t.check(&b0), None);
        // b00, b000, b01, b010, b011 were discarded along with the b0 subtree
        // when finality first advanced (to b1 via add(b102)) — they're on a
        // permanently-dead fork and got dropped from the tree.
        assert_eq!(t.check(&b00), None);
        assert_eq!(t.check(&b000), None);
        assert_eq!(t.check(&b01), None);
        assert_eq!(t.check(&b010), None);
        assert_eq!(t.check(&b011), None);
        // b1 was removed by window-prune (too old, newer final blocks).
        assert_eq!(t.check(&b1), None);
        assert_eq!(t.check(&b10), Some(BlockStatus::Final));
        assert_eq!(t.check(&b100), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b11), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b110), Some(BlockStatus::OptimisticButNotCanonical));
        assert_eq!(t.check(&b111), Some(BlockStatus::OptimisticButNotCanonical));

        let b10200 = b1020.descendant(11);
        let b102000 = b10200.descendant(12);
        let b1020000 = b102000.descendant(13);
        assert_eq!(&t.add(&b10200, "b10200"), "");
        assert_eq!(&t.add(&b102000, "b102000"), "");
        assert_eq!(&t.add(&b1020000, "b1020000"), "b102,b1020,b10200");

        //    Recent blocks: (Window = 9 to 13, GC limit 9)
        //    ├─[9]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "b001"
        //    ├─[9]     8jRJjsyqjoAbyWbjLXTjFNiKTwT8s4xspouvRaZGfh6R "b010"
        //    ├─[10]     CnbxNBi2SVDZo9z8V8kwrmE3pUkozpDvpCCg9Tq25rY3 "b011"
        // FH ├─[11] C F NW4CWxr6ptWa9tsV2gMhGPdE7ecNWfCrnJDfJwx9yv9 "b10200"
        //    │ [12] C   4Vwtcagaq6fi5j82suG4j8HiaU3SMbqotrZzT3bjqwcP "b102000"
        // CH │ [13] C   GktyudcCf3dBkWCdjq9dFssY7KZRRZQJ1TZH3ZMw8LWk "b1020000"
        //    ├─[9]     6E2vqjZLbuUY2y6VK571Ai3pk43EUHXuNxibJuBGh44T "b110"
        //    └─[10]     Cq9uMZqNZr6zuF7nT6yfGms1ptaVVu5dAdiRJ6pqCTN8 "b111"
        t.print();
        // b001, b010, b011 were already discarded earlier (with the b0 subtree).
        // b110, b111 are discarded by add(b1020000)'s finality jump to b10200,
        // along with the rest of the b1 dead-fork branch (b11, b100, b101).
        assert_eq!(t.check(&b001), None);
        assert_eq!(t.check(&b010), None);
        assert_eq!(t.check(&b011), None);
        assert_eq!(t.check(&b10200), Some(BlockStatus::Final));
        assert_eq!(t.check(&b102000), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(
            t.check(&b1020000),
            Some(BlockStatus::OptimisticAndCanonical)
        );
        assert_eq!(t.check(&b110), None);
        assert_eq!(t.check(&b111), None);
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

        tester.add(&b1, "1");
        tester.add(&b2, "2");
        tester.add(&b4, "4");
        tester.add(&b5, "5");

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
        tester.add(&b6, "6");

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
        tester.add(&b1, "1");
        tester.add(&b2, "2");
        tester.add(&b3, "3");
        tester.add(&b3_fork, "3f");
        tester.add(&b4, "4");
        tester.add(&b4_fork, "4f");

        // Sanity checks
        assert_eq!(tester.check(&b1), Some(BlockStatus::Final));
        assert_eq!(tester.check(&b2), Some(BlockStatus::Final));

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
        tester.add(&b5, "5");

        // Then: We expect b3_fork subtree to be pruned and b2 to become the new root
        //   (b2, F)               ← new root
        //    │
        //   (b3, F)
        //    │
        //   (b4)
        //    │
        //   (b5)

        //   Check that b3_fork was removed:
        assert_eq!(tester.check(&b3_fork), None);
        assert_eq!(tester.check(&b4_fork), None);
        assert!(
            weak_b3_fork.upgrade().is_none(),
            "dead-fork BlockNode b3_fork leaked — prune_dead_children did not detach"
        );
        assert!(
            weak_b4_fork.upgrade().is_none(),
            "dead-fork BlockNode b4_fork leaked — descendant of detached dead-fork not freed"
        );

        // Additional sanity checks:
        // b1 should have been removed:
        assert_eq!(tester.check(&b1), None);
        // b2, b3 should now be final
        assert_eq!(tester.check(&b2), Some(BlockStatus::Final));
        assert_eq!(tester.check(&b3), Some(BlockStatus::Final));
        // b4, b5 should be optimistic and canonical
        assert_eq!(tester.check(&b4), Some(BlockStatus::OptimisticAndCanonical));
        assert_eq!(tester.check(&b5), Some(BlockStatus::OptimisticAndCanonical));
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
        tester.add(&b1, "1");
        tester.add(&b2, "2");
        tester.add(&b3, "3");
        assert_eq!(tester.tracker.minimum_height_to_keep(), Some(1))
    }
}
