use derive_more::{Deref, From, Into};
use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;
use serde::{Deserialize, Serialize};

/// Dstack event log, a.k.a. the TCB Info.
#[derive(From, Deref, Into, Serialize, Deserialize)]
pub struct TcbInfo(DstackTcbInfo);
