use derive_more::{Deref, From, Into};
use dstack_sdk::dstack_client::TcbInfo as DstackTcbInfo;
use serde::{Deserialize, Serialize};

/// Dstack event log, a.k.a. the TCB Info.
#[derive(Serialize, Deserialize, From, Deref, Into)]
pub struct TcbInfo(DstackTcbInfo);
