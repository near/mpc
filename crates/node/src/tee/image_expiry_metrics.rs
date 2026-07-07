use mpc_primitives::hash::NodeImageHash;
use near_mpc_contract_interface::types::AllowedMpcDockerImageHash;

use crate::metrics::{
    MPC_OWN_IMAGE_HASH_ALLOWED, MPC_OWN_IMAGE_HASH_EXPIRY_TIMESTAMP_SECONDS,
    MPC_OWN_IMAGE_HASH_IS_MOST_RECENT,
};

/// Indicates if no expiration date is known.
const NO_EXPIRY: i64 = -1;

/// Updates the own-image-hash gauges from the latest allowed images.
pub fn update_own_image_hash_gauges(
    current_image: &NodeImageHash,
    allowed_images: &[AllowedMpcDockerImageHash],
) {
    let Some((allowed, is_most_recent, expiry_timestamp_seconds)) =
        infer_image_status(current_image, allowed_images)
    else {
        return;
    };
    MPC_OWN_IMAGE_HASH_ALLOWED.set(allowed.into());
    MPC_OWN_IMAGE_HASH_IS_MOST_RECENT.set(is_most_recent.into());
    MPC_OWN_IMAGE_HASH_EXPIRY_TIMESTAMP_SECONDS.set(expiry_timestamp_seconds);
}

/// Returns a tuple:
/// - first bool indicates if `current_image` is still valid
/// - second bool indicates if `current_image` is the most recent image_hash
/// - last value indicates expiry timestamp (-1 if no expiry timestamp is given)
/// Expects `allowed_images` to be in increasing order of expiration timestamp
fn infer_image_status(
    current_image: &NodeImageHash,
    allowed_images: &[AllowedMpcDockerImageHash],
) -> Option<(bool, bool, i64)> {
    // TODO(#3751): simplify this function after updating the contract
    if allowed_images.is_empty() {
        return None;
    }

    let is_most_recent = allowed_images
        .first()
        .is_some_and(|newest| newest.image_hash == *current_image);

    Some(
        match allowed_images
            .iter()
            .find(|entry| entry.image_hash == *current_image)
        {
            Some(entry) => match entry.expiry_timestamp_seconds {
                Some(expires_at) => (
                    true,
                    is_most_recent,
                    i64::try_from(expires_at).unwrap_or(i64::MAX),
                ),
                None => (true, is_most_recent, NO_EXPIRY),
            },
            None => (false, false, 0),
        },
    )
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    const EXPIRES_AT: u64 = 1_754_000_000;

    fn image_hash(val: u8) -> NodeImageHash {
        NodeImageHash::from([val; 32])
    }

    /// Newest-first, like the contract view: hash 1 never expires, hash 2 is
    /// evicted at [`EXPIRES_AT`].
    fn allowed_images() -> Vec<AllowedMpcDockerImageHash> {
        vec![
            AllowedMpcDockerImageHash {
                image_hash: image_hash(1),
                expiry_timestamp_seconds: None,
            },
            AllowedMpcDockerImageHash {
                image_hash: image_hash(2),
                expiry_timestamp_seconds: Some(EXPIRES_AT),
            },
        ]
    }

    #[rstest]
    #[case::newest_hash_never_expires(allowed_images(), 1, Some((true, true, NO_EXPIRY)))]
    #[case::older_hash_reports_eviction_time(allowed_images(), 2, Some((true, false, EXPIRES_AT as i64)))]
    #[case::evicted_hash_is_not_allowed(allowed_images(), 9, Some((false, false, 0)))]
    #[case::empty_list_is_ignored(vec![], 1, None)]
    fn own_image_status__should_report_allowed_most_recent_and_eviction_time(
        #[case] allowed_images: Vec<AllowedMpcDockerImageHash>,
        #[case] current_image: u8,
        #[case] expected: Option<(bool, bool, i64)>,
    ) {
        // When
        let status = infer_image_status(&image_hash(current_image), &allowed_images);

        // Then
        assert_eq!(status, expected);
    }
}
