use std::path::{Path, PathBuf};

use crate::port_allocator::E2ePortAllocator;

pub struct NearSandbox {
    _rpc_port: u16,
    _network_port: u16,
}

impl NearSandbox {
    pub async fn start(
        _ports: &E2ePortAllocator,
        _image: &str,
        _test_dir: &Path,
    ) -> anyhow::Result<Self> {
        unimplemented!("Docker sandbox implementation — see Change 2")
    }

    pub fn rpc_url(&self) -> String {
        unimplemented!()
    }

    pub fn genesis_path(&self) -> PathBuf {
        unimplemented!()
    }

    pub fn boot_nodes(&self) -> anyhow::Result<String> {
        unimplemented!()
    }

    pub fn chain_id(&self) -> anyhow::Result<String> {
        unimplemented!()
    }
}
