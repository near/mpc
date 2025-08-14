use serde_yaml::Value as YamlValue;

use crate::common::{
    TEST_LAUNCHER_IMAGE_COMPOSE_NORMALIZED_STRING, TEST_LAUNCHER_IMAGE_COMPOSE_STRING,
};

pub mod common;

#[test]
fn test_launcher_compose_normalization() {
    let launcher_image_compose: YamlValue =
        serde_yaml::from_str(TEST_LAUNCHER_IMAGE_COMPOSE_STRING).unwrap();
    let launcher_image_compose_normalized_str =
        serde_yaml::to_string(&launcher_image_compose).unwrap();
    assert_eq!(
        launcher_image_compose_normalized_str,
        TEST_LAUNCHER_IMAGE_COMPOSE_NORMALIZED_STRING
    );

    let launcher_image_compose_normalized: YamlValue =
        serde_yaml::from_str(TEST_LAUNCHER_IMAGE_COMPOSE_NORMALIZED_STRING).unwrap();
    assert_eq!(launcher_image_compose, launcher_image_compose_normalized);
}
