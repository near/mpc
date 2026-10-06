//! Types exchanged between MPC nodes and Blaire.

use serde::{Deserialize, Serialize};

pub type Version = String;

/// The Node report, the redacted report is received in JSON format
#[derive(Debug, Deserialize, Serialize)]
pub struct NodeReport{
    pub version: Version,
    pub redacted_report: RedactedConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RedactedConfig {}