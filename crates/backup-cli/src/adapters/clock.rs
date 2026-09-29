use std::time::{SystemTime, UNIX_EPOCH};

use crate::ports::WallClock;

pub struct SystemClock;

impl WallClock for SystemClock {
    fn unix_now_seconds(&self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|elapsed| elapsed.as_secs())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn unix_now_seconds__should_answer_a_present_day_time() {
        let now = SystemClock.unix_now_seconds();

        // 2023-11-14; anything later proves the clock is read, not made up.
        assert!(now.is_some_and(|now| now > 1_700_000_000), "{now:?}");
    }
}
