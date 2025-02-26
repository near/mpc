use near_indexer_primitives::views::BlockView;
use near_indexer_primitives::CryptoHash;
use std::cell::{Cell, Ref, RefCell};
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Add;
use std::rc::Rc;

pub struct RecentBlocksTracker {
    heights_to_keep: u64,
    root_children: Vec<Rc<BlockNode>>,
    canonical_head: Option<Rc<BlockNode>>,
    final_head: Option<Rc<BlockNode>>,
    hash_to_node: HashMap<CryptoHash, Rc<BlockNode>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckBlockResult {
    /// The block is within the recent window, and also finalized by the blockchain
    /// (it is an ancestor (including self) of the latest final block).
    RecentAndFinal,
    /// The block is recent enough, but belongs to a different fork so has no chance
    /// of being included in the blockchain.
    NotIncluded,
    /// The block is optimistically included in the chain, and it is on the canonical chain,
    /// but it is not yet part of the final chain.
    /// Note: If such a block is older than the recent window but still not finalized, this
    /// will still be returned instead of returning OlderThanRecentWindow.
    OptimisticAndCanonical,
    /// The block is optimistically included in the chain, but it is not on the canonical chain.
    /// Note: If such a block is older than the recent window but still not finalized, this
    /// will still be returned instead of returning OlderThanRecentWindow.
    OptimisticButNotCanonical,
    /// The block is older than the recent window of blocks we keep.
    OlderThanRecentWindow,
    /// We have not seen the block yet.
    Unknown,
}

struct BlockNode {
    hash: CryptoHash,
    height: u64,
    canonical: Cell<bool>,
    is_final: Cell<bool>,
    parent: RefCell<Option<Rc<BlockNode>>>,
    children: RefCell<Vec<Rc<BlockNode>>>,
}

impl BlockNode {
    fn closest_descendants_with_height_at_least(
        self: &Rc<BlockNode>,
        height: u64,
        descendants_output: &mut Vec<Rc<BlockNode>>,
        old_nodes: &mut Vec<Rc<BlockNode>>,
    ) {
        if self.height >= height {
            descendants_output.push(self.clone());
        } else {
            old_nodes.push(self.clone());
            let children = self.children.borrow();
            for child in children.iter() {
                child.closest_descendants_with_height_at_least(
                    height,
                    descendants_output,
                    old_nodes,
                );
            }
        }
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
        writeln!(
            f,
            "[{}] {} {} {:?}",
            self.height,
            if self.canonical.get() { "C" } else { " " },
            if self.is_final.get() { "F" } else { " " },
            self.hash
        )?;
        let children = self.children.borrow();
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

pub struct BlockViewLite {
    pub hash: CryptoHash,
    pub height: u64,
    pub prev_hash: CryptoHash,
    pub last_final_block: CryptoHash,
}

impl RecentBlocksTracker {
    pub fn new(heights_to_keep: u64) -> Self {
        Self {
            heights_to_keep,
            root_children: Vec::new(),
            canonical_head: None,
            final_head: None,
            hash_to_node: HashMap::new(),
        }
    }

    pub fn add_block(&mut self, block: &BlockViewLite) {
        let parent = self.hash_to_node.get(&block.prev_hash).cloned();
        let node = Rc::new(BlockNode {
            hash: block.hash,
            height: block.height,
            canonical: Cell::new(false),
            is_final: Cell::new(false),
            parent: RefCell::new(parent.clone()),
            children: RefCell::new(Vec::new()),
        });
        self.hash_to_node.insert(block.hash, node.clone());
        if let Some(parent) = parent {
            parent.children.borrow_mut().push(node.clone());
        } else {
            self.root_children.push(node.clone());
        }

        self.update_final_head(block.last_final_block);
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
        self.prune_old_blocks();
    }

    fn update_final_head(&mut self, final_head: CryptoHash) {
        let final_head_node = self.hash_to_node.get(&final_head);
        if let Some(final_head_node) = final_head_node {
            let mut node = final_head_node.clone();
            loop {
                if node.is_final.get() {
                    break;
                }
                node.is_final.set(true);
                let Some(parent) = node.parent.borrow().clone() else {
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
    }

    fn update_canonical_head(&mut self, new_canonical_head: &Rc<BlockNode>) {
        let mut node = Some(new_canonical_head.clone());

        while let Some(current_node) = node {
            if current_node.canonical.get() {
                node = Some(current_node);
                break;
            }
            current_node.canonical.set(true);
            node = current_node.parent.borrow().clone();
        }
        let common_ancestor = node;

        let mut old_node = self.canonical_head.clone();
        while let Some(current_node) = old_node {
            if let Some(common_ancestor) = &common_ancestor {
                if Rc::ptr_eq(&current_node, common_ancestor) {
                    break;
                }
            }
            current_node.canonical.set(false);
            old_node = current_node.parent.borrow().clone();
        }
        self.canonical_head = Some(new_canonical_head.clone());
    }

    fn minimum_height_to_keep(&self) -> Option<u64> {
        let Some(final_head) = &self.final_head else {
            return None;
        };
        let Some(canonical_head) = &self.canonical_head else {
            return None;
        };
        Some(
            canonical_head
                .height
                .saturating_sub(self.heights_to_keep)
                .add(1)
                .min(final_head.height),
        )
    }

    fn prune_old_blocks(&mut self) {
        let Some(minimum_height_to_keep) = self.minimum_height_to_keep() else {
            return;
        };
        // Note: unwrap() cannot fail because we have at least one block in the tree.
        if self
            .root_children
            .iter()
            .map(|child| child.height)
            .min()
            .unwrap()
            >= minimum_height_to_keep
        {
            return;
        }

        let mut new_root_children = Vec::new();
        let mut old_nodes = Vec::new();
        for child in &self.root_children {
            child.closest_descendants_with_height_at_least(
                minimum_height_to_keep,
                &mut new_root_children,
                &mut old_nodes,
            );
        }
        for child in &new_root_children {
            *child.parent.borrow_mut() = None;
        }
        self.root_children = new_root_children;
        for old_node in old_nodes {
            self.hash_to_node.remove(&old_node.hash);
        }
    }

    pub fn check_block(&self, block_hash: CryptoHash, block_height: u64) -> CheckBlockResult {
        match self.hash_to_node.get(&block_hash) {
            Some(node) => {
                if node.is_final.get() {
                    return CheckBlockResult::RecentAndFinal;
                }
                if let Some(final_head) = &self.final_head {
                    if block_height <= final_head.height {
                        return CheckBlockResult::NotIncluded;
                    }
                }
                if node.canonical.get() {
                    return CheckBlockResult::OptimisticAndCanonical;
                }
                return CheckBlockResult::OptimisticButNotCanonical;
            }
            None => {
                if let Some(minimum_height_to_keep) = self.minimum_height_to_keep() {
                    if block_height < minimum_height_to_keep {
                        return CheckBlockResult::OlderThanRecentWindow;
                    }
                }
                // At this point, the block is recent enough but we have not seen it yet.
                // We could do a few more checks to narrow down the case, but it's not really
                // worth the complexity. So just return Unknown.
                return CheckBlockResult::Unknown;
            }
        }
    }
}

impl Debug for RecentBlocksTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.minimum_height_to_keep() {
            Some(height) => {
                writeln!(f, "   Recent blocks (keeping blocks >= height {}):", height)?;
            }
            None => {
                writeln!(f, "   Recent blocks (not enough information yet to calculate minimum height to keep):")?;
            }
        }
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
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockViewLite, RecentBlocksTracker};
    use crate::signing::recent_blocks_tracker::CheckBlockResult;
    use near_indexer::near_primitives::hash::hash;
    use near_indexer_primitives::CryptoHash;
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;
    use std::rc::Rc;

    struct TestBlock {
        hash: CryptoHash,
        height: u64,
        parent: Option<Rc<TestBlock>>,

        tester: Rc<TestBlockMaker>,
        next_fork_seed: Cell<u64>,
    }

    struct TestBlockMaker {
        root_blocks: RefCell<Vec<Rc<TestBlock>>>,
        final_head: RefCell<Option<Rc<TestBlock>>>,
    }

    impl TestBlock {
        pub fn last_final_block(self: &TestBlock) -> Option<Rc<TestBlock>> {
            let Some(parent) = self.parent.clone() else {
                return None;
            };
            let Some(grandparent) = parent.parent.clone() else {
                return parent.last_final_block();
            };
            if grandparent.height + 1 == parent.height && parent.height + 1 == self.height {
                return Some(grandparent);
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
                prev_hash: parent_hash,
                last_final_block: last_final_block_hash,
            }
        }

        pub fn child(self: &Rc<TestBlock>, height: u64) -> Rc<TestBlock> {
            assert!(
                height > self.height,
                "Height must be greater than the parent height"
            );

            if let Some(final_head) = self.tester.final_head.borrow().clone() {
                let mut node = self.clone();
                loop {
                    if Rc::ptr_eq(&node, &final_head) {
                        break;
                    }
                    if let Some(parent) = node.parent.clone() {
                        node = parent;
                    } else {
                        panic!("Parent is not a descendant of the final head");
                    }
                }
            }

            let next_fork_seed = self.next_fork_seed.get();
            self.next_fork_seed.set(next_fork_seed + 1);

            let hash_seed = self
                .hash
                .0
                .iter()
                .chain(next_fork_seed.to_be_bytes().iter())
                .copied()
                .collect::<Vec<_>>();
            let block = Rc::new(TestBlock {
                hash: hash(&hash_seed),
                height,
                parent: Some(self.clone()),
                tester: self.tester.clone(),
                next_fork_seed: Cell::new(0),
            });
            *self.tester.final_head.borrow_mut() = block.last_final_block();
            block
        }
    }

    impl TestBlockMaker {
        pub fn block(self: &Rc<Self>, height: u64) -> Rc<TestBlock> {
            let hash_seed: Vec<u8> = b"root"
                .iter()
                .chain(self.root_blocks.borrow().len().to_be_bytes().iter())
                .copied()
                .collect();
            let block = Rc::new(TestBlock {
                hash: hash(&hash_seed),
                height,
                parent: None,
                tester: self.clone(),
                next_fork_seed: Cell::new(0),
            });
            self.root_blocks.borrow_mut().push(block.clone());
            block
        }
    }

    struct Tester {
        maker: Rc<TestBlockMaker>,
        tracker: RecentBlocksTracker,
        parents_of_added_blocks: HashSet<CryptoHash>,
    }

    impl Tester {
        pub fn new(heights_to_keep: u64) -> Self {
            let maker = Rc::new(TestBlockMaker {
                root_blocks: RefCell::new(Vec::new()),
                final_head: RefCell::new(None),
            });
            let tracker = RecentBlocksTracker::new(heights_to_keep);
            Self {
                maker,
                tracker,
                parents_of_added_blocks: HashSet::new(),
            }
        }

        pub fn block(&self, height: u64) -> Rc<TestBlock> {
            self.maker.block(height)
        }

        pub fn check_block(&self, block: &Rc<TestBlock>) -> CheckBlockResult {
            self.tracker.check_block(block.hash, block.height)
        }

        pub fn add(&mut self, block: &Rc<TestBlock>) -> &mut Self {
            assert!(
                !self.parents_of_added_blocks.contains(&block.hash),
                "Cannot retroactively add the parent of an already added block"
            );
            self.tracker.add_block(&block.to_block_view());
            if let Some(parent) = block.parent.clone() {
                self.parents_of_added_blocks.insert(parent.hash);
            }
            self
        }

        pub fn print(&self) {
            println!("{:?}", self.tracker);
        }
    }

    #[test]
    fn test_no_forks() {
        let mut tester = Tester::new(4);
        let b10 = tester.block(10);
        let b11 = b10.child(11);
        let b12 = b11.child(12);
        let b13 = b12.child(13);
        let b14 = b13.child(14);
        let b15 = b14.child(15);
        let b16 = b15.child(16);

        tester.add(&b11).add(&b12).add(&b13).add(&b14).add(&b15);
        tester.print();

        // At this point, the tracker should keep blocks 12, 13, 14, 15.
        assert_eq!(
            tester.check_block(&b10),
            CheckBlockResult::OlderThanRecentWindow
        );
        assert_eq!(
            tester.check_block(&b11),
            CheckBlockResult::OlderThanRecentWindow
        );
        assert_eq!(tester.check_block(&b12), CheckBlockResult::RecentAndFinal);
        assert_eq!(tester.check_block(&b13), CheckBlockResult::RecentAndFinal);
        assert_eq!(
            tester.check_block(&b14),
            CheckBlockResult::OptimisticAndCanonical
        );
        assert_eq!(
            tester.check_block(&b15),
            CheckBlockResult::OptimisticAndCanonical
        );
        assert_eq!(tester.check_block(&b16), CheckBlockResult::Unknown);
    }

    #[test]
    fn test_simple_forks() {
        let mut tester = Tester::new(5);
        let b10 = tester.block(10);
        let b11 = b10.child(11);
        let b12 = b11.child(12);
        let b13 = b12.child(13);
        // Start forks (last final block is 11)
        let b14 = b12.child(14);
        let b15 = b13.child(15);
        let b16 = b12.child(16);
        let b17 = b13.child(17);

        tester.add(&b11).add(&b12).add(&b13);
        tester.add(&b14).add(&b16);
        tester.add(&b15);

        // Recent blocks (keeping blocks >= height 11):
        // FH └─[11] C F F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA
        //      [12] C   7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG
        //      ├─[13]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt
        //      │ [15]     4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA
        //      ├─[14]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz
        // CH   └─[16] C   81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG
        tester.print();

        assert_eq!(
            tester.check_block(&b10),
            CheckBlockResult::OlderThanRecentWindow
        );
        // Even though 11 is older than the window, we keep at least one final block.
        assert_eq!(tester.check_block(&b11), CheckBlockResult::RecentAndFinal);
        assert_eq!(
            tester.check_block(&b12),
            CheckBlockResult::OptimisticAndCanonical
        );
        assert_eq!(
            tester.check_block(&b13),
            CheckBlockResult::OptimisticButNotCanonical
        );
        assert_eq!(
            tester.check_block(&b14),
            CheckBlockResult::OptimisticButNotCanonical
        );
        assert_eq!(
            tester.check_block(&b15),
            CheckBlockResult::OptimisticButNotCanonical
        );
        assert_eq!(
            tester.check_block(&b16),
            CheckBlockResult::OptimisticAndCanonical
        );
        assert_eq!(tester.check_block(&b17), CheckBlockResult::Unknown);

        let b18 = b14.child(18);
        tester.add(&b18);
        // Recent blocks (keeping blocks >= height 11):
        // FH └─[11] C F F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA
        //      [12] C   7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG
        //      ├─[13]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt
        //      │ [15]     4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA
        //      ├─[14] C   DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz
        // CH   │ [18] C   GHjy91467tR3nyE2ycq9JM4MH22ZoBZCrkXSEFnT7Vhp
        //      └─[16]     81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG
        tester.print();

        assert_eq!(
            tester.check_block(&b14),
            CheckBlockResult::OptimisticAndCanonical
        );
        assert_eq!(
            tester.check_block(&b16),
            CheckBlockResult::OptimisticButNotCanonical
        );
        assert_eq!(
            tester.check_block(&b18),
            CheckBlockResult::OptimisticAndCanonical
        );

        let b19 = b18.child(19);
        let b20 = b19.child(20);

        tester.add(&b19).add(&b20);
        // Recent blocks (keeping blocks >= height 16):
        // FH ├─[18] C F GHjy91467tR3nyE2ycq9JM4MH22ZoBZCrkXSEFnT7Vhp
        //    │ [19] C   DtoqtibWnNxpvqwgXUXDMrawHNQPP2AC8p3fjdiZvtKg
        // CH │ [20] C   24aEbuUrHRACVS8Ty27pbWnBygML7QBttQo44trWLen7
        //    └─[16]     81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG
        tester.print();

        assert_eq!(
            tester.check_block(&b14),
            CheckBlockResult::OlderThanRecentWindow
        );
        assert_eq!(
            tester.check_block(&b15),
            CheckBlockResult::OlderThanRecentWindow
        );
        assert_eq!(tester.check_block(&b16), CheckBlockResult::NotIncluded);
        assert_eq!(tester.check_block(&b17), CheckBlockResult::Unknown);
        assert_eq!(tester.check_block(&b18), CheckBlockResult::RecentAndFinal);
        assert_eq!(
            tester.check_block(&b19),
            CheckBlockResult::OptimisticAndCanonical
        );
        assert_eq!(
            tester.check_block(&b20),
            CheckBlockResult::OptimisticAndCanonical
        );
    }
}
