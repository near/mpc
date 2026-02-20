#[derive(Debug, Clone)]
pub struct IndexerStats {
    pub block_heights_processing: std::collections::BTreeSet<u64>,
    pub blocks_processed_count: u64,
    pub last_processed_block_height: u64,
}

impl Default for IndexerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexerStats {
    pub fn new() -> Self {
        Self {
            block_heights_processing: std::collections::BTreeSet::new(),
            blocks_processed_count: 0,
            last_processed_block_height: 0,
        }
    }
}
