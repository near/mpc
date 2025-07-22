# test_launcher_config.py
import inspect

import tempfile
from tee_launcher.launcher import parse_env_lines

from tee_launcher.launcher import (
    parse_env_file,
    build_docker_cmd,
    is_valid_host_entry,
    is_valid_port_mapping,
)


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
        "PORTS": "11780:11780,--env BAD=1",
        "EXTRA_HOSTS": "node:192.168.1.1,--volume /:/mnt",
        "MPC_ACCOUNT_ID": "mpc-user-123",
    }
    cmd = build_docker_cmd(env, "sha256:abc123")

    func_name = inspect.currentframe().f_code.co_name
    print(f"[{func_name}] CMD:", " ".join(cmd))

    assert "--env" in cmd
    assert "MPC_ACCOUNT_ID=mpc-user-123" in cmd
    assert "-p" in cmd
    assert "11780:11780" in cmd
    assert "--add-host" in cmd
    assert "node:192.168.1.1" in cmd

    # Make sure injection strings were filtered
    assert not any("BAD=1" in arg for arg in cmd)
    assert not any("/:/mnt" in arg for arg in cmd)


def test_extra_hosts_does_not_allow_ld_preload():
    env = {
        "EXTRA_HOSTS": "host:1.2.3.4,--env LD_PRELOAD=/evil.so",
        "MPC_ACCOUNT_ID": "safe",
    }
    cmd = build_docker_cmd(env, "sha256:abc123")

    assert "host:1.2.3.4" in cmd
    assert not any("LD_PRELOAD" in arg for arg in cmd)


def test_ports_does_not_allow_volume_injection():
    env = {
        "PORTS": "2200:2200,--volume /:/mnt",
        "MPC_ACCOUNT_ID": "safe",
    }
    cmd = build_docker_cmd(env, "sha256:abc123")

    assert "2200:2200" in cmd
    assert not any("/:/mnt" in arg for arg in cmd)


def test_invalid_env_key_is_ignored():
    env = {
        "BAD_KEY": "should_not_be_used",
        "MPC_ACCOUNT_ID": "safe",
    }
    cmd = build_docker_cmd(env, "sha256:abc123")

    assert "should_not_be_used" not in " ".join(cmd)
    assert "MPC_ACCOUNT_ID=safe" in cmd


def test_malformed_extra_host_is_ignored():
    env = {
        "EXTRA_HOSTS": "badhostentry,no-colon,also--bad",
        "MPC_ACCOUNT_ID": "safe",
    }
    cmd = build_docker_cmd(env, "sha256:abc123")

    assert "--add-host" not in cmd  # All malformed entries should be skipped


def test_env_value_with_shell_injection_is_handled_safely():
    env = {
        "MPC_ACCOUNT_ID": "safe; rm -rf /",
    }
    cmd = build_docker_cmd(env, "sha256:abc123")

    assert "--env" in cmd
    assert "MPC_ACCOUNT_ID=safe; rm -rf /" in cmd


def test_parse_and_build_docker_cmd_full_flow():
    config_str = """
    # Valid entries
    MPC_ACCOUNT_ID=test-user
    PORTS=11780:11780, --env BAD=oops
    EXTRA_HOSTS=host1:192.168.1.1, --volume /:/mnt
    IMAGE_HASH=sha256:abc123
    """

    env = parse_env_string(config_str)
    image_hash = env.get("IMAGE_HASH", "sha256:default")

    cmd = build_docker_cmd(env, image_hash)

    print(f"[{inspect.currentframe().f_code.co_name}] CMD: {' '.join(cmd)}")

    assert "--env" in cmd
    assert "MPC_ACCOUNT_ID=test-user" in cmd
    assert "-p" in cmd
    assert "11780:11780" in cmd
    assert "--add-host" in cmd
    assert "host1:192.168.1.1" in cmd

    # Confirm malicious injection is blocked
    assert not any("--env BAD=oops" in s or "oops" in s for s in cmd)
    assert not any("/:/mnt" in s for s in cmd)


# Test that ensures LD_PRELOAD cannot be injected into the docker command
def test_ld_preload_injection_blocked1():
    # Set up the environment variable with a dangerous LD_PRELOAD value
    malicious_env = {
        "MPC_ACCOUNT_ID": "mpc-user-123",
        "--env LD_PRELOAD": "/path/to/my/malloc.so",  # The dangerous value
    }

    # Call build_docker_cmd to generate the docker command
    docker_cmd = build_docker_cmd(malicious_env, "sha256:abc123")

    # Check that LD_PRELOAD is not included in the command
    assert "--env" in docker_cmd  # Ensure there is an env var
    assert (
        "LD_PRELOAD" not in docker_cmd
    )  # Make sure LD_PRELOAD is not in the generated command

    # Alternatively, if you're using a regex to ensure safe environment variables
    assert not any(
        "-e " in arg for arg in docker_cmd
    )  # Ensure no CLI injection for LD_PRELOAD


# Additional tests can go here for host/port validation


# Test that ensures LD_PRELOAD cannot be injected through extra hosts
def test_ld_preload_in_extra_hosts1():
    # Set up environment with malicious EXRA_HOSTS containing LD_PRELOAD
    malicious_env = {
        "MPC_ACCOUNT_ID": "mpc-user-123",
        "EXTRA_HOSTS": "host1:192.168.0.1,host2:192.168.0.2,--env LD_PRELOAD=/path/to/my/malloc.so",
    }

    # Call build_docker_cmd to generate the docker command
    docker_cmd = build_docker_cmd(malicious_env, "sha256:abc123")

    # Check that LD_PRELOAD is not part of the extra hosts in the docker command
    assert "--add-host" in docker_cmd  # Ensure extra hosts are included
    assert "LD_PRELOAD" not in docker_cmd  # Ensure LD_PRELOAD is NOT in the command

    # Check that there are no malicious injections
    assert not any(
        "--env LD_PRELOAD" in arg for arg in docker_cmd
    )  # No environment injection


# Test that ensures LD_PRELOAD cannot be injected through ports
def test_ld_preload_in_ports1():
    # Set up environment with malicious PORTS containing LD_PRELOAD
    malicious_env = {
        "MPC_ACCOUNT_ID": "mpc-user-123",
        "PORTS": "11780:11780,--env LD_PRELOAD=/path/to/my/malloc.so",
    }

    # Call build_docker_cmd to generate the docker command
    docker_cmd = build_docker_cmd(malicious_env, "sha256:abc123")

    # Check that LD_PRELOAD is not part of the port mappings in the docker command
    assert "-p" in docker_cmd  # Ensure port mappings are included
    assert "LD_PRELOAD" not in docker_cmd  # Ensure LD_PRELOAD is NOT in the command

    # Check that there are no malicious injections
    assert not any(
        "--env LD_PRELOAD" in arg for arg in docker_cmd
    )  # No environment injection


# Additional tests could go here to check other edge cases


# Test that ensures LD_PRELOAD cannot be injected through mpc account id
def test_ld_preload_in_mpc_account_id():
    # Set up environment with malicious EXRA_HOSTS containing LD_PRELOAD
    malicious_env = {
        "MPC_ACCOUNT_ID": "mpc-user-123, --env LD_PRELOAD=/path/to/my/malloc.so",
        "EXTRA_HOSTS": "host1:192.168.0.1,host2:192.168.0.2",
    }

    # Call build_docker_cmd to generate the docker command
    docker_cmd = build_docker_cmd(malicious_env, "sha256:abc123")

    # Check that LD_PRELOAD is not part of the extra hosts in the docker command
    assert "--add-host" in docker_cmd  # Ensure extra hosts are included
    assert "LD_PRELOAD" not in docker_cmd  # Ensure LD_PRELOAD is NOT in the command

    # Check that there are no malicious injections
    print(docker_cmd)
    assert not any(
        "--env LD_PRELOAD" in arg for arg in docker_cmd
    )  # No environment injection


# Test that ensures LD_PRELOAD cannot be injected into the docker command
def test_ld_preload_injection_blocked2():
    # Set up the environment variable with a dangerous LD_PRELOAD value
    malicious_env = {
        "MPC_ACCOUNT_ID": "mpc-user-123",
        "-e LD_PRELOAD": "/path/to/my/malloc.so",  # The dangerous value
    }

    # Call build_docker_cmd to generate the docker command
    docker_cmd = build_docker_cmd(malicious_env, "sha256:abc123")

    assert (
        "-e LD_PRELOAD" not in docker_cmd
    )  # Make sure LD_PRELOAD is not in the generated command


# Additional tests can go here for host/port validation


# Test that ensures LD_PRELOAD cannot be injected through extra hosts
def test_ld_preload_in_extra_hosts2():
    # Set up environment with malicious EXRA_HOSTS containing LD_PRELOAD
    malicious_env = {
        "MPC_ACCOUNT_ID": "mpc-user-123",
        "EXTRA_HOSTS": "host1:192.168.0.1,host2:192.168.0.2,-e LD_PRELOAD=/path/to/my/malloc.so",
    }

    # Call build_docker_cmd to generate the docker command
    docker_cmd = build_docker_cmd(malicious_env, "sha256:abc123")

    # Check that LD_PRELOAD is not part of the extra hosts in the docker command
    assert "--add-host" in docker_cmd  # Ensure extra hosts are included
    assert "LD_PRELOAD" not in docker_cmd  # Ensure LD_PRELOAD is NOT in the command


# Test that ensures LD_PRELOAD cannot be injected through ports
def test_ld_preload_in_ports2():
    # Set up environment with malicious PORTS containing LD_PRELOAD
    malicious_env = {
        "MPC_ACCOUNT_ID": "mpc-user-123",
        "PORTS": "11780:11780,-e LD_PRELOAD=/path/to/my/malloc.so",
    }

    # Call build_docker_cmd to generate the docker command
    docker_cmd = build_docker_cmd(malicious_env, "sha256:abc123")

    # Check that LD_PRELOAD is not part of the port mappings in the docker command
    assert "-p" in docker_cmd  # Ensure port mappings are included
    assert "LD_PRELOAD" not in docker_cmd  # Ensure LD_PRELOAD is NOT in the command


# Additional tests could go here to check other edge cases
