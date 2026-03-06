# test_launcher_config.py

import inspect
import json
import os
import tempfile
import tee_launcher.launcher as launcher


import pytest
from unittest.mock import mock_open

from tee_launcher.launcher import (
    load_and_select_hash,
    validate_image_hash,
    parse_env_lines,
    build_docker_cmd,
    is_valid_host_entry,
    is_valid_port_mapping,
    Platform,
    get_mpc_config_path,
)
from tee_launcher.launcher import (
    JSON_KEY_APPROVED_HASHES,
    ENV_VAR_MPC_HASH_OVERRIDE,
    ENV_VAR_DEFAULT_IMAGE_DIGEST,
)


# Test constants for user_config content
TEST_MPC_ACCOUNT_ID = "mpc-user-123"

TEST_PORTS_WITH_INJECTION = "11780:11780,--env BAD=1"

TEST_EXTRA_HOSTS_WITH_IP = "node:192.168.1.1"
TEST_EXTRA_HOSTS_WITH_INJECTION = f"{TEST_EXTRA_HOSTS_WITH_IP},--volume /:/mnt"


def make_digest_json(hashes):
    return json.dumps({JSON_KEY_APPROVED_HASHES: hashes})


def parse_env_string(text: str) -> dict:
    return parse_env_lines(text.splitlines())


def test_parse_env_lines_basic():
    lines = [
        "# a comment",
        "KEY1=value1",
        "  KEY2 = value2 ",
        "",
        "INVALIDLINE",
        "EMPTY_KEY=",
    ]
    env = parse_env_lines(lines)
    assert env == {"KEY1": "value1", "KEY2": "value2", "EMPTY_KEY": ""}


# test user config loading and parsing
def write_temp_config(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def test_valid_user_config_parsing():
    config_str = """
    MPC_ACCOUNT_ID=account123
    MPC_LOCAL_ADDRESS=127.0.0.1
    # A comment
    MPC_ENV=testnet
    """
    env = parse_env_string(config_str)

    assert env["MPC_ACCOUNT_ID"] == "account123"
    assert env["MPC_LOCAL_ADDRESS"] == "127.0.0.1"
    assert env["MPC_ENV"] == "testnet"


def test_config_ignores_blank_lines_and_comments():
    config_str = """

    # This is a comment
    MPC_SECRET_STORE_KEY=topsecret

    """
    env = parse_env_string(config_str)

    assert env["MPC_SECRET_STORE_KEY"] == "topsecret"
    assert len(env) == 1


def test_config_skips_malformed_lines():
    config_str = """
    GOOD_KEY=value
    bad_line_without_equal
    ANOTHER_GOOD=ok
    =
    """
    env = parse_env_string(config_str)

    assert "GOOD_KEY" in env
    assert "ANOTHER_GOOD" in env
    assert "bad_line_without_equal" not in env
    assert "" not in env  # ensure empty keys are skipped


def test_config_overrides_duplicate_keys():
    config_str = """
    MPC_ACCOUNT_ID=first
    MPC_ACCOUNT_ID=second
    """
    env = parse_env_string(config_str)

    assert env["MPC_ACCOUNT_ID"] == "second"  # last one wins


# test valid and invalid host entries and port mappings


def test_valid_host_entry():
    assert is_valid_host_entry("node.local:192.168.1.1")
    assert not is_valid_host_entry("node.local:not-an-ip")
    assert not is_valid_host_entry("--env LD_PRELOAD=hack.so")


def test_valid_port_mapping():
    assert is_valid_port_mapping("11780:11780")
    assert not is_valid_port_mapping("65536:11780")
    assert not is_valid_port_mapping("--volume /:/mnt")


def test_build_docker_cmd_sanitizes_ports_and_hosts():
    env = {
        "PORTS": TEST_PORTS_WITH_INJECTION,
        "EXTRA_HOSTS": TEST_EXTRA_HOSTS_WITH_INJECTION,
    }
    cmd = build_docker_cmd(launcher.Platform.TEE, env, "sha256:abc123")

    func_name = inspect.currentframe().f_code.co_name
    print(f"[{func_name}] CMD:", " ".join(cmd))

    assert "-p" in cmd
    assert "11780:11780" in cmd
    assert "--add-host" in cmd
    assert TEST_EXTRA_HOSTS_WITH_IP in cmd

    # Make sure injection strings were filtered
    assert not any("BAD=1" in arg for arg in cmd)
    assert not any("/:/mnt" in arg for arg in cmd)

    # Verify config file is passed as command arg
    assert "start-with-config-file" in cmd


def test_extra_hosts_does_not_allow_ld_preload():
    env = {
        "EXTRA_HOSTS": "host:1.2.3.4,--env LD_PRELOAD=/evil.so",
    }
    cmd = build_docker_cmd(launcher.Platform.TEE, env, "sha256:abc123")

    assert "host:1.2.3.4" in cmd
    assert not any("LD_PRELOAD" in arg for arg in cmd)


def test_ports_does_not_allow_volume_injection():
    env = {
        "PORTS": "2200:2200,--volume /:/mnt",
    }
    cmd = build_docker_cmd(launcher.Platform.TEE, env, "sha256:abc123")

    assert "2200:2200" in cmd
    assert not any("/:/mnt" in arg for arg in cmd)


def test_malformed_extra_host_is_ignored():
    env = {
        "EXTRA_HOSTS": "badhostentry,no-colon,also--bad",
    }
    cmd = build_docker_cmd(launcher.Platform.TEE, env, "sha256:abc123")

    assert "--add-host" not in cmd  # All malformed entries should be skipped


def test_parse_and_build_docker_cmd_full_flow():
    config_str = """
    # Valid entries
    PORTS=11780:11780, --env BAD=oops
    EXTRA_HOSTS=host1:192.168.1.1, --volume /:/mnt
    """

    env = parse_env_string(config_str)

    cmd = build_docker_cmd(launcher.Platform.TEE, env, "sha256:abc123")

    print(f"[{inspect.currentframe().f_code.co_name}] CMD: {' '.join(cmd)}")

    assert "-p" in cmd
    assert "11780:11780" in cmd
    assert "--add-host" in cmd
    assert "host1:192.168.1.1" in cmd

    # Confirm malicious injection is blocked
    assert not any("--env BAD=oops" in s or "oops" in s for s in cmd)
    assert not any("/:/mnt" in s for s in cmd)


# Test that ensures LD_PRELOAD cannot be injected into the docker command
def test_ld_preload_injection_blocked1():
    malicious_env = {
        "--env LD_PRELOAD": "/path/to/my/malloc.so",
    }

    docker_cmd = build_docker_cmd(launcher.Platform.TEE, malicious_env, "sha256:abc123")

    assert (
        "LD_PRELOAD" not in docker_cmd
    )


def test_ld_preload_in_extra_hosts1():
    malicious_env = {
        "EXTRA_HOSTS": "host1:192.168.0.1,host2:192.168.0.2,--env LD_PRELOAD=/path/to/my/malloc.so",
    }

    docker_cmd = build_docker_cmd(launcher.Platform.TEE, malicious_env, "sha256:abc123")

    assert "--add-host" in docker_cmd
    assert "LD_PRELOAD" not in docker_cmd


def test_ld_preload_in_ports1():
    malicious_env = {
        "PORTS": "11780:11780,--env LD_PRELOAD=/path/to/my/malloc.so",
    }

    docker_cmd = build_docker_cmd(launcher.Platform.TEE, malicious_env, "sha256:abc123")

    assert "-p" in docker_cmd
    assert "LD_PRELOAD" not in docker_cmd


def test_ld_preload_injection_blocked2():
    malicious_env = {
        "-e LD_PRELOAD": "/path/to/my/malloc.so",
    }

    docker_cmd = build_docker_cmd(launcher.Platform.TEE, malicious_env, "sha256:abc123")

    assert (
        "-e LD_PRELOAD" not in docker_cmd
    )


def test_ld_preload_in_extra_hosts2():
    malicious_env = {
        "EXTRA_HOSTS": "host1:192.168.0.1,host2:192.168.0.2,-e LD_PRELOAD=/path/to/my/malloc.so",
    }

    docker_cmd = build_docker_cmd(launcher.Platform.TEE, malicious_env, "sha256:abc123")

    assert "--add-host" in docker_cmd
    assert "LD_PRELOAD" not in docker_cmd


def test_ld_preload_in_ports2():
    malicious_env = {
        "PORTS": "11780:11780,-e LD_PRELOAD=/path/to/my/malloc.so",
    }

    docker_cmd = build_docker_cmd(launcher.Platform.TEE, malicious_env, "sha256:abc123")

    assert "-p" in docker_cmd
    assert "LD_PRELOAD" not in docker_cmd


def test_json_key_matches_node():
    """
    Ensure the JSON key used by the launcher to read approved image hashes
    stays aligned with the MPC node implementation.
    mpc/crates/node/src/tee/allowed_image_hashes_watcher.rs -> JSON_KEY_APPROVED_HASHES

    If this test fails, it means the launcher and MPC node are using different
    JSON field names, which would break MPC hash propagation.
    """
    assert launcher.JSON_KEY_APPROVED_HASHES == "approved_hashes"


def test_override_present(monkeypatch):
    override_value = "sha256:" + "a" * 64
    approved = ["sha256:" + "b" * 64, override_value, "sha256:" + "c" * 64]

    fake_json = make_digest_json(approved)

    monkeypatch.setattr("tee_launcher.launcher.os.path.isfile", lambda _: True)
    monkeypatch.setattr("builtins.open", mock_open(read_data=fake_json))

    dstack_config = {ENV_VAR_MPC_HASH_OVERRIDE: override_value}

    selected = load_and_select_hash(dstack_config)
    assert selected == override_value


def test_override_not_present(monkeypatch):
    approved = ["sha256:aaa", "sha256:bbb"]
    fake_json = make_digest_json(approved)

    monkeypatch.setattr("tee_launcher.launcher.os.path.isfile", lambda _: True)
    monkeypatch.setattr("builtins.open", mock_open(read_data=fake_json))

    dstack_config = {
        ENV_VAR_MPC_HASH_OVERRIDE: "sha256:xyz"  # NOT in list
    }

    with pytest.raises(RuntimeError):
        load_and_select_hash(dstack_config)


def test_no_override_picks_newest(monkeypatch):
    approved = ["sha256:newest", "sha256:older", "sha256:oldest"]
    fake_json = make_digest_json(approved)

    monkeypatch.setattr("tee_launcher.launcher.os.path.isfile", lambda _: True)
    monkeypatch.setattr("builtins.open", mock_open(read_data=fake_json))

    selected = load_and_select_hash({})
    assert selected == "sha256:newest"


def test_missing_file_fallback(monkeypatch):
    # Pretend file does NOT exist
    monkeypatch.setattr("tee_launcher.launcher.os.path.isfile", lambda _: False)

    # Valid fallback digest (64 hex chars)
    monkeypatch.setenv(ENV_VAR_DEFAULT_IMAGE_DIGEST, "a" * 64)

    selected = load_and_select_hash({})
    assert selected == "sha256:" + "a" * 64


TEST_DIGEST = "sha256:f2472280c437efc00fa25a030a24990ae16c4fbec0d74914e178473ce4d57372"
# Important: ensure the config matches your test image
DSTACK_CONFIG = {
    "MPC_IMAGE_TAGS": "83b52da4e2270c688cdd30da04f6b9d3565f25bb",
    "MPC_IMAGE_NAME": "nearone/testing",
    "MPC_REGISTRY": "registry.hub.docker.com",
}

# Launcher defaults
RPC_REQUEST_TIMEOUT_SECS = 10.0
RPC_REQUEST_INTERVAL_SECS = 1.0
RPC_MAX_ATTEMPTS = 20


# ------------------------------------------------------------------------------------
# NOTE: Integration Test (External Dependency)
#
# This test validates that `validate_image_hash()` correctly:
#   - contacts the real Docker registry,
#   - resolves the manifest digest,
#   - pulls the remote image,
#   - and verifies that its sha256 digest matches the expected immutable value.
#
# The test image is a **pre-built, minimal Docker image containing only a tiny
# binary**, created intentionally for performance and fast pulls.
# This image is uploaded to Docker Hub together.
#
# IMPORTANT:
#   • The digest in this test corresponds EXACTLY to that pre-built image.
#   • Dockerfile used to build the image can be found at mpc/tee_launcher/launcher-test-image/Dockerfile
#   • If the test image is rebuilt, the digest MUST be updated here.
#   • If the registry is unavailable or slow, this test may fail.
#   • CI will run this only if explicitly enabled.
#
# Please read that file before modifying the digest, registry, or test behavior.
# ------------------------------------------------------------------------------------
def test_validate_image_hash():
    result = validate_image_hash(
        TEST_DIGEST,
        DSTACK_CONFIG,
        RPC_REQUEST_TIMEOUT_SECS,
        RPC_REQUEST_INTERVAL_SECS,
        RPC_MAX_ATTEMPTS,
    )
    assert result is True, "validate_image_hash() failed for test image"


# test launcher support for non TEE images.


class DummyProc:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def base_env(monkeypatch):
    # Required by launcher
    monkeypatch.setenv(launcher.OS_ENV_DOCKER_CONTENT_TRUST, "1")
    monkeypatch.setenv(launcher.ENV_VAR_DEFAULT_IMAGE_DIGEST, "sha256:" + "a" * 64)


def test_parse_platform_missing(monkeypatch, base_env):
    monkeypatch.delenv(launcher.ENV_VAR_PLATFORM, raising=False)
    with pytest.raises(RuntimeError):
        launcher.parse_platform()


@pytest.mark.parametrize("val", ["", "foo", "TEE as", "NON_TEE", "1", "tee", "nontee"])
def test_parse_platform_invalid(monkeypatch, base_env, val):
    monkeypatch.setenv(launcher.ENV_VAR_PLATFORM, val)
    with pytest.raises(RuntimeError):
        launcher.parse_platform()


@pytest.mark.parametrize(
    "val,expected",
    [
        ("TEE", launcher.Platform.TEE),
        ("NONTEE", launcher.Platform.NONTEE),
    ],
)
def test_parse_platform_valid(monkeypatch, base_env, val, expected):
    monkeypatch.setenv(launcher.ENV_VAR_PLATFORM, val)
    assert launcher.parse_platform() is expected


def test_extend_rtmr3_nontee_skips_dstack(monkeypatch, base_env):
    called = {"count": 0}

    def fake_curl(*args, **kwargs):
        called["count"] += 1
        return DummyProc(returncode=0)

    monkeypatch.setattr(launcher, "curl_unix_socket_post", fake_curl)

    launcher.extend_rtmr3(launcher.Platform.NONTEE, "sha256:" + "b" * 64)
    assert called["count"] == 0


def test_extend_rtmr3_tee_requires_socket(monkeypatch, base_env):
    monkeypatch.setattr(launcher, "is_unix_socket", lambda p: False)
    with pytest.raises(RuntimeError):
        launcher.extend_rtmr3(launcher.Platform.TEE, "sha256:" + "b" * 64)


def test_extend_rtmr3_tee_getquote_fail(monkeypatch, base_env):
    monkeypatch.setattr(launcher, "is_unix_socket", lambda p: True)

    def fake_curl(endpoint, payload, capture_output=False):
        # Fail only GetQuote
        if endpoint == "GetQuote":
            return DummyProc(returncode=7)
        return DummyProc(returncode=0)

    monkeypatch.setattr(launcher, "curl_unix_socket_post", fake_curl)
    with pytest.raises(RuntimeError, match="GetQuote failed"):
        launcher.extend_rtmr3(launcher.Platform.TEE, "sha256:" + "b" * 64)


def test_extend_rtmr3_tee_emitevent_fail(monkeypatch, base_env):
    monkeypatch.setattr(launcher, "is_unix_socket", lambda p: True)

    def fake_curl(endpoint, payload, capture_output=False):
        if endpoint == "GetQuote":
            return DummyProc(returncode=0)
        if endpoint == "EmitEvent":
            return DummyProc(returncode=55)
        return DummyProc(returncode=0)

    monkeypatch.setattr(launcher, "curl_unix_socket_post", fake_curl)
    with pytest.raises(RuntimeError, match="EmitEvent failed"):
        launcher.extend_rtmr3(launcher.Platform.TEE, "sha256:" + "b" * 64)


def test_build_docker_cmd_nontee_no_dstack_mount(base_env):
    env = {
        # launcher-only env should be ignored
        launcher.ENV_VAR_RPC_MAX_ATTEMPTS: "5",
    }
    cmd = launcher.build_docker_cmd(launcher.Platform.NONTEE, env, "sha256:" + "c" * 64)
    s = " ".join(cmd)

    assert f"{launcher.DSTACK_UNIX_SOCKET}:{launcher.DSTACK_UNIX_SOCKET}" not in s
    # Config file path should be passed as command arg
    assert "start-with-config-file" in cmd


def test_build_docker_cmd_tee_has_dstack_mount(base_env):
    env = {}
    cmd = launcher.build_docker_cmd(launcher.Platform.TEE, env, "sha256:" + "c" * 64)
    s = " ".join(cmd)

    assert f"{launcher.DSTACK_UNIX_SOCKET}:{launcher.DSTACK_UNIX_SOCKET}" in s
    assert "start-with-config-file" in cmd


def test_build_docker_cmd_no_env_passthrough():
    """Ensure no --env flags are emitted (all config via file now)."""
    env = {
        "MPC_ACCOUNT_ID": "test",
        "MPC_CONTRACT_ID": "contract.near",
        "RUST_LOG": "info",
    }
    cmd = build_docker_cmd(Platform.NONTEE, env, "sha256:" + "a" * 64)
    assert "--env" not in cmd


def test_build_docker_cmd_passes_config_file_path():
    env = {}
    cmd = build_docker_cmd(Platform.NONTEE, env, "sha256:" + "a" * 64)

    # Should end with: <image_digest> start-with-config-file <path>
    assert cmd[-2] == "start-with-config-file"
    assert cmd[-1] == launcher.DEFAULT_MPC_CONFIG_PATH


def test_build_docker_cmd_custom_config_path():
    env = {launcher.DSTACK_USER_CONFIG_MPC_CONFIG_PATH: "/tapp/custom_config.json"}
    cmd = build_docker_cmd(Platform.NONTEE, env, "sha256:" + "a" * 64)

    assert cmd[-2] == "start-with-config-file"
    assert cmd[-1] == "/tapp/custom_config.json"


def test_get_mpc_config_path_default():
    assert get_mpc_config_path({}) == launcher.DEFAULT_MPC_CONFIG_PATH


def test_get_mpc_config_path_override():
    config = {launcher.DSTACK_USER_CONFIG_MPC_CONFIG_PATH: "/tapp/my_config.json"}
    assert get_mpc_config_path(config) == "/tapp/my_config.json"


def test_main_tee_fails_closed_before_launch(monkeypatch, base_env):
    monkeypatch.setenv(launcher.ENV_VAR_PLATFORM, launcher.Platform.TEE.value)

    monkeypatch.setattr(launcher, "is_unix_socket", lambda p: False)

    # prevent any real docker/network
    monkeypatch.setattr(
        launcher, "load_and_select_hash", lambda cfg: "sha256:" + "d" * 64
    )
    monkeypatch.setattr(launcher, "validate_image_hash", lambda *a, **k: True)
    monkeypatch.setattr(
        launcher,
        "launch_mpc_container",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not launch")),
    )

    with pytest.raises(RuntimeError, match="requires dstack unix socket"):
        launcher.main()


def test_main_nontee_skips_extend_and_launches(monkeypatch, base_env):
    monkeypatch.setenv(launcher.ENV_VAR_PLATFORM, "NONTEE")
    monkeypatch.setattr(
        launcher, "is_unix_socket", lambda p: False
    )  # should not matter

    monkeypatch.setattr(
        launcher, "load_and_select_hash", lambda cfg: "sha256:" + "d" * 64
    )
    monkeypatch.setattr(launcher, "validate_image_hash", lambda *a, **k: True)

    called = {"extend": 0, "launch": 0}
    monkeypatch.setattr(
        launcher,
        "extend_rtmr3",
        lambda platform, h: called.__setitem__("extend", called["extend"] + 1),
    )
    monkeypatch.setattr(
        launcher,
        "launch_mpc_container",
        lambda platform, h, cfg: called.__setitem__("launch", called["launch"] + 1),
    )

    launcher.main()
    assert called["extend"] == 1
    assert called["launch"] == 1


def assert_subsequence(seq, subseq):
    it = iter(seq)
    for x in subseq:
        for y in it:
            if y == x:
                break
        else:
            raise AssertionError(f"Missing subsequence item: {x}\nseq={seq}")


def test_main_nontee_builds_expected_mpc_docker_cmd(monkeypatch, tmp_path):
    """
    Verify that launcher.main() builds the correct MPC docker command in NONTEE mode.
    Config is now passed as a file path argument, not via env vars.
    """
    # --- Arrange: environment (NONTEE) ---
    monkeypatch.setenv(launcher.ENV_VAR_PLATFORM, launcher.Platform.NONTEE.value)
    monkeypatch.setenv(launcher.OS_ENV_DOCKER_CONTENT_TRUST, "1")

    default_digest = "sha256:" + "a" * 64
    monkeypatch.setenv(launcher.ENV_VAR_DEFAULT_IMAGE_DIGEST, default_digest)

    # Provide a temp user config file with ports and extra hosts
    user_config = tmp_path / "user_config"
    user_config.write_text(
        "\n".join(
            [
                f"PORTS={TEST_PORTS_WITH_INJECTION}",  # injection should be ignored
                f"EXTRA_HOSTS={TEST_EXTRA_HOSTS_WITH_INJECTION}",  # injection should be ignored
            ]
        )
        + "\n"
    )

    # Point launcher at our temp config
    monkeypatch.setattr(launcher, "DSTACK_USER_CONFIG_FILE", str(user_config))

    # Make IMAGE_DIGEST_FILE "missing" so DEFAULT_IMAGE_DIGEST is used
    def fake_isfile(path: str) -> bool:
        if path == launcher.IMAGE_DIGEST_FILE:
            return False
        if path == str(user_config):
            return True
        return os.path.isfile(path)

    monkeypatch.setattr(launcher.os.path, "isfile", fake_isfile)

    # Avoid network/docker verification in validate_image_hash
    monkeypatch.setattr(launcher, "validate_image_hash", lambda *a, **k: True)

    # Avoid remove_existing_container touching real docker
    monkeypatch.setattr(launcher, "check_output", lambda *a, **k: "")

    # Capture the docker run command used to launch MPC
    captured = {"docker_run_cmd": None}

    def fake_run(cmd, *args, **kwargs):
        # cmd is a list[str]
        if (
            isinstance(cmd, list)
            and len(cmd) >= 2
            and cmd[0] == "docker"
            and cmd[1] == "run"
        ):
            captured["docker_run_cmd"] = cmd
            return DummyProc(returncode=0)
        return DummyProc(returncode=0)

    monkeypatch.setattr(launcher, "run", fake_run)

    # --- Act ---
    launcher.main()

    # --- Assert ---
    cmd = captured["docker_run_cmd"]
    assert cmd is not None, "Expected launcher to invoke 'docker run' for MPC container"

    cmd_str = " ".join(cmd)

    # NONTEE invariants: no dstack socket mount
    assert f"{launcher.DSTACK_UNIX_SOCKET}:{launcher.DSTACK_UNIX_SOCKET}" not in cmd_str

    # No env passthrough (all config is via file now)
    assert "--env" not in cmd

    # Docker networking still works
    assert "-p" in cmd and "11780:11780" in cmd_str
    assert "--add-host" in cmd and TEST_EXTRA_HOSTS_WITH_IP in cmd_str

    # Injection strings filtered out
    assert "BAD=1" not in cmd_str
    assert "/:/mnt" not in cmd_str

    # Required mounts / flags from build_docker_cmd
    assert "--security-opt" in cmd_str
    assert "no-new-privileges:true" in cmd_str
    assert "/tapp:/tapp:ro" in cmd_str
    assert "shared-volume:/mnt/shared" in cmd_str
    assert "mpc-data:/data" in cmd_str
    assert f"--name {launcher.MPC_CONTAINER_NAME}" in cmd_str

    # Config file is passed as command arg after the image digest
    digest_idx = cmd.index(default_digest)
    assert cmd[digest_idx + 1] == "start-with-config-file"
    assert cmd[digest_idx + 2] == launcher.DEFAULT_MPC_CONFIG_PATH

    expected_core = [
        "docker",
        "run",
        "--security-opt",
        "no-new-privileges:true",
        "-v",
        "/tapp:/tapp:ro",
        "-v",
        "shared-volume:/mnt/shared",
        "-v",
        "mpc-data:/data",
        "--name",
        launcher.MPC_CONTAINER_NAME,
        "--detach",
    ]
    assert_subsequence(cmd, expected_core)
