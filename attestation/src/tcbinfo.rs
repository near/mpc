use derive_more::{Deref, From, Into};
use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;

/// Dstack event log, a.k.a. the TCB Info.
#[derive(From, Deref, Into)]
pub struct TcbInfo(DstackTcbInfo);
