use near_sdk::near;
use std::time::Duration;

#[near(serializers=[json])]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TimeStamp {
    duration_since_unix_epoch: Duration,
}

impl TimeStamp {
    pub(crate) fn now() -> Self {
        let time_stamp_now = near_sdk::env::block_timestamp_ms();

        Self {
            duration_since_unix_epoch: Duration::from_millis(time_stamp_now),
        }
    }

    pub(crate) fn checked_sub(self, other: TimeStamp) -> Option<Duration> {
        self.duration_since_unix_epoch
            .checked_sub(other.duration_since_unix_epoch)
    }
}

impl borsh::BorshSerialize for TimeStamp {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let duration_milliseconds: u64 = self.duration_since_unix_epoch.as_secs();
        let duration_milliseconds_bytes: [u8; 8] = duration_milliseconds.to_be_bytes();

        writer.write_all(&duration_milliseconds_bytes)
    }
}

impl borsh::BorshDeserialize for TimeStamp {
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
        let timestamp_one = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(100),
        };
        let timestamp_two = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(100),
        };
        assert_eq!(timestamp_one, timestamp_two);
    }

    #[test]
    fn test_timestamp_ordering() {
        let earlier_timestamp = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(50),
        };
        let later_timestamp = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(100),
        };

        assert!(earlier_timestamp < later_timestamp);
        assert!(later_timestamp > earlier_timestamp);
        assert!(earlier_timestamp <= later_timestamp);
        assert!(later_timestamp >= earlier_timestamp);
    }

    #[test]
    fn test_checked_sub_positive_duration() {
        let larger_timestamp = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(200),
        };
        let smaller_timestamp = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(150),
        };

        let duration_difference = larger_timestamp.checked_sub(smaller_timestamp);
        assert_eq!(duration_difference, Some(Duration::from_secs(50)));
    }

    #[test]
    fn test_checked_sub_zero_difference() {
        let timestamp_one = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(1234),
        };
        let timestamp_two = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(1234),
        };

        let duration_difference = timestamp_one.checked_sub(timestamp_two);
        assert_eq!(duration_difference, Some(Duration::ZERO));
    }

    #[test]
    fn test_checked_sub_negative_returns_none() {
        let smaller_timestamp = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(50),
        };
        let larger_timestamp = TimeStamp {
            duration_since_unix_epoch: Duration::from_secs(100),
        };

        let duration_difference = smaller_timestamp.checked_sub(larger_timestamp);
        assert_eq!(duration_difference, None);
    }
}
