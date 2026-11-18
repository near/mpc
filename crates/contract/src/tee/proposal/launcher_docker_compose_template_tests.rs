use serde_yaml::Value;

use super::LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE;

fn parsed_template() -> Value {
    serde_yaml::from_str(LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE).unwrap()
}

fn key_paths(value: &Value, parent: &str) -> Vec<String> {
    match value {
        Value::Mapping(mapping) => mapping
            .iter()
            .flat_map(|(key, value)| {
                let path = format!("{parent}{}", key.as_str().unwrap());
                let nested_paths = key_paths(value, &format!("{path}."));
                std::iter::once(path).chain(nested_paths)
            })
            .collect(),
        Value::Sequence(items) => items
            .iter()
            .flat_map(|item| key_paths(item, parent))
            .collect(),
        Value::Tagged(tagged) => key_paths(&tagged.value, parent),
        _ => Vec::new(),
    }
}

#[test]
fn launcher_docker_compose_template__should_not_use_variable_substitution() {
    // Given
    let template = LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE;

    // When
    let lines_with_substitution: Vec<&str> =
        template.lines().filter(|line| line.contains('$')).collect();

    // Then
    assert_eq!(lines_with_substitution, Vec::<&str>::new());
}

#[test]
fn launcher_docker_compose_template__should_only_use_reviewed_keys() {
    // Given
    let template = parsed_template();

    // When
    let keys = key_paths(&template, "");

    // Then
    assert_eq!(
        keys,
        [
            "version",
            "services",
            "services.launcher",
            "services.launcher.image",
            "services.launcher.container_name",
            "services.launcher.environment",
            "services.launcher.volumes",
            "services.launcher.devices",
            "services.launcher.security_opt",
            "services.launcher.read_only",
            "services.launcher.tmpfs",
            "volumes",
            "volumes.shared-volume",
            "volumes.shared-volume.name",
        ]
    );
}

#[test]
fn launcher_docker_compose_template__should_set_a_value_for_every_environment_variable() {
    // Given
    let template = parsed_template();

    // When
    let variables_without_value: Vec<&str> = template["services"]["launcher"]["environment"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .filter(|entry| !entry.contains('='))
        .collect();

    // Then
    assert_eq!(variables_without_value, Vec::<&str>::new());
}
