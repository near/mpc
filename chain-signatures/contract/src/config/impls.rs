use borsh::{self, BorshDeserialize, BorshSerialize};

use super::{Config, DynamicValue};

impl Config {
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        let value = self.entries.get(key)?;
        Some(&value.0)
    }
}

impl From<serde_json::Value> for DynamicValue {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}
impl BorshSerialize for DynamicValue {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let buf = serde_json::to_vec(&self.0)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        BorshSerialize::serialize(&buf, writer)
    }
}

impl BorshDeserialize for DynamicValue {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let buf: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let value = serde_json::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self(value))
    }
}

pub const fn secs_to_ms(secs: u64) -> u64 {
    secs * 1000
}

pub const fn min_to_ms(min: u64) -> u64 {
    min * 60 * 1000
}
