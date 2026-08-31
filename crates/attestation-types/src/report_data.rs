/// Number of bytes for the report data.
pub const REPORT_DATA_SIZE: usize = 64;

#[derive(Debug, Clone, derive_more::From)]
pub struct ReportData([u8; REPORT_DATA_SIZE]);

impl ReportData {
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        self.0
    }
}
