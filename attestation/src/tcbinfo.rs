use derive_more::{Deref, From};
use dstack_sdk::dstack_client::TcbInfo as DstackTcbInfo;

/// Dstack event log, a.k.a. the TCB Info.
#[derive(From, Deref)]
pub struct TcbInfo(DstackTcbInfo);
