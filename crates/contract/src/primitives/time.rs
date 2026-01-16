use std::time::Duration;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Timestamp {
    duration_since_unix_epoch: Duration,
}

impl Timestamp {
    pub(crate) fn now() -> Self {
        let block_time_nano_seconds = near_sdk::env::block_timestamp();

        Self {
            duration_since_unix_epoch: Duration::from_nanos(block_time_nano_seconds),
        }
    }

    pub(crate) fn checked_add(self, duration: Duration) -> Option<Self> {
        let current_time_stamp = self.duration_since_unix_epoch;
        let new_time_stamp = current_time_stamp.checked_add(duration)?;

        Some(Timestamp {
            duration_since_unix_epoch: new_time_stamp,
        })
    }
}

impl borsh::BorshSerialize for Timestamp {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let duration_milliseconds: u64 = self.duration_since_unix_epoch.as_secs();
        let duration_milliseconds_bytes: [u8; 8] = duration_milliseconds.to_be_bytes();

        writer.write_all(&duration_milliseconds_bytes)
    }
}

impl borsh::BorshDeserialize for Timestamp {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut duration_milliseconds_bytes: [u8; 8] = [0; 8];
        reader.read_exact(&mut duration_milliseconds_bytes)?;

        let duration_milliseconds = u64::from_be_bytes(duration_milliseconds_bytes);
        let duration_since_unix_epoch = Duration::from_secs(duration_milliseconds);

        Ok(Self {
            duration_since_unix_epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_timestamp_equality() {
        let timestamp_one = Timestamp {
            duration_since_unix_epoch: Duration::from_secs(100),
        };
        let timestamp_two = Timestamp {
            duration_since_unix_epoch: Duration::from_secs(100),
        };
        assert_eq!(timestamp_one, timestamp_two);
    }

    #[test]
    fn test_timestamp_ordering() {
        let earlier_timestamp = Timestamp {
            duration_since_unix_epoch: Duration::from_secs(50),
        };
        let later_timestamp = Timestamp {
            duration_since_unix_epoch: Duration::from_secs(100),
        };

        assert!(earlier_timestamp < later_timestamp);
        assert!(later_timestamp > earlier_timestamp);
        assert!(earlier_timestamp <= later_timestamp);
        assert!(later_timestamp >= earlier_timestamp);
    }

    #[test]
    fn test_checked_add_succeeds() {
        let time_stamp = Timestamp {
            duration_since_unix_epoch: Duration::from_secs(200),
        };
        let added_duration = Duration::from_secs(100);

        let expected_time_stamp = Timestamp {
            duration_since_unix_epoch: Duration::from_secs(300),
        };

        let new_time_stamp = time_stamp.checked_add(added_duration);
        assert_eq!(new_time_stamp, Some(expected_time_stamp));
    }

    #[test]
    fn test_checked_add_overflow_returns_none() {
        let max_time_stamp = Timestamp {
            duration_since_unix_epoch: Duration::from_secs(u64::MAX),
        };

        let added_duration = Duration::from_secs(100);

        let new_time_stamp = max_time_stamp.checked_add(added_duration);

        assert_eq!(new_time_stamp, None);
    }
}
