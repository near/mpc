use launcher_interface::types::{ApprovedHashes, DockerSha256Digest};

use crate::error::LauncherError;

/// Select which image hash to use, given the approved hashes file (if present),
/// a fallback default digest, and an optional user override.
///
/// Selection rules:
///   - If the approved hashes file is absent → use `default_digest`
///   - If `override_hash` is set and appears in the approved list → use it
///   - If `override_hash` is set but NOT in the approved list → error
///   - Otherwise → use the newest approved hash (first in the list)
pub fn select_image_hash(
    approved_hashes: Option<&ApprovedHashes>,
    default_digest: &DockerSha256Digest,
    override_hash: Option<&DockerSha256Digest>,
) -> Result<DockerSha256Digest, LauncherError> {
    let Some(approved) = approved_hashes else {
        tracing::info!("no approved hashes file, using default digest");
        return Ok(default_digest.clone());
    };

    if let Some(override_image) = override_hash {
        tracing::info!(?override_image, "override mpc image hash provided");
        if !approved.approved_hashes.contains(override_image) {
            return Err(LauncherError::InvalidHashOverride(format!(
                "MPC_HASH_OVERRIDE={override_image} does not match any approved hash",
            )));
        }
        return Ok(override_image.clone());
    }

    let selected = approved.newest_approved_hash().clone();
    tracing::info!(?selected, "selected newest approved hash");
    Ok(selected)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use launcher_interface::types::{ApprovedHashes, DockerSha256Digest};
    use near_mpc_bounded_collections::NonEmptyVec;
    use rstest::rstest;
    use std::assert_matches;

    use super::*;

    fn digest(hex_char: char) -> DockerSha256Digest {
        format!(
            "sha256:{}",
            std::iter::repeat_n(hex_char, 64).collect::<String>()
        )
        .parse()
        .unwrap()
    }

    fn approved_file(hashes: Vec<DockerSha256Digest>) -> ApprovedHashes {
        ApprovedHashes {
            approved_hashes: NonEmptyVec::from_vec(hashes).unwrap(),
        }
    }

    fn sample_digest() -> DockerSha256Digest {
        digest('a')
    }

    #[rstest]
    #[case::override_present_and_in_approved_list(vec!['c', 'b', 'd'], Some('b'), 'b')]
    #[case::no_override_picks_newest(vec!['a', 'b', 'c'], None, 'a')]
    fn select_image_hash__should_return_expected_hash_from_approved_list(
        #[case] approved_chars: Vec<char>,
        #[case] override_char: Option<char>,
        #[case] expected_char: char,
    ) {
        // Given
        let approved = approved_file(approved_chars.into_iter().map(digest).collect());
        let override_digest = override_char.map(digest);

        // When
        let result = select_image_hash(Some(&approved), &digest('f'), override_digest.as_ref());

        // Then
        assert_eq!(result.unwrap(), digest(expected_char));
    }

    #[test]
    fn select_hash_override_not_in_approved_list() {
        // given
        let override_digest = digest('b');
        let approved = approved_file(vec![digest('c'), digest('d')]);

        // when
        let result = select_image_hash(Some(&approved), &digest('f'), Some(&override_digest));

        // then
        assert_matches!(result, Err(LauncherError::InvalidHashOverride(_)));
    }

    #[rstest]
    #[case::falls_back_to_default(None)]
    #[case::ignores_override(Some('b'))]
    fn select_image_hash__should_return_default_when_file_missing(
        #[case] override_char: Option<char>,
    ) {
        // Given
        let default = digest('d');
        let override_digest = override_char.map(digest);

        // When
        let result = select_image_hash(None, &default, override_digest.as_ref());

        // Then
        assert_eq!(result.unwrap(), default);
    }

    // --- approved_hashes JSON key alignment ---

    #[test]
    fn approved_hashes_json_key_is_approved_hashes() {
        // given - the JSON field name must match between launcher and MPC node
        let file = approved_file(vec![sample_digest()]);

        // when
        let json = serde_json::to_value(&file).unwrap();

        // then
        assert!(json.get("approved_hashes").is_some());
    }
}
