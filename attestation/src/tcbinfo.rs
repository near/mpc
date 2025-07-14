use dstack_sdk::dstack_client::TcbInfo as DstackTcbInfo;

/// Dstack event log, a.k.a. the TCB Info.
pub struct TcbInfo(DstackTcbInfo);
