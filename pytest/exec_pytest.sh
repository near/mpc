#!/bin/bash

# -------------------------------------------------------------------
# Script Name: exec_pytest.sh
# Description: Compiles nearcore and mpc node,
#              activates a virtual environment with the required python dependencies,
#              saves output to `output.log`.
#
# Usage:
# - Run the script with optional flags:
#   --reset-submodules : Resets git submodules.
#   --verbose          : Enables detailed log output.
#   --non-reproducible : Disables reproducible contract build
#
# Example:
#   bash exec_pytest.sh --reset-submodules --verbose --non-reproducible
#
# Requirements:
# - bash
# - Git
# - Python 3 with venv module
#
# -------------------------------------------------------------------

LOG_FILE="output.log"
log_output() {
    if [ "$VERBOSE" = true ]; then
        "$@" 2>&1 | tee -a "$LOG_FILE"
        local cmd_exit_code=${PIPESTATUS[0]} # Get the exit code of the first command in the pipeline
        return "$cmd_exit_code"
    else
        # Progress indicator
        local progress_pid
        {
            while :; do
                printf "." >&2
                sleep 5
            done
        } &

        trap 'kill $progress_pid 2>/dev/null' EXIT

        progress_pid=$!
        local temp_stderr
        temp_stderr=$(mktemp)
        "$@" >"$LOG_FILE" 2> >(tee "$temp_stderr" >&2)
        local cmd_exit_code=${PIPESTATUS[0]} # Get the exit code of the first command in the pipeline

        kill "$progress_pid" 2>/dev/null
        wait "$progress_pid" 2>/dev/null
        cat "$temp_stderr" >>"$LOG_FILE"
        rm -f "$temp_stderr"

        trap - EXIT
        return "$cmd_exit_code"
    fi
}

if ! GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    printf "\nError: Not inside a Git repository.\n"
    exit 1
fi

echo "Git repository root: $GIT_ROOT"
PYTEST_DIR="$GIT_ROOT/pytest"
VENV_DIR="$PYTEST_DIR/venv"
LIB_DIR="$GIT_ROOT/libs"

REQ_DIRS=(
    "$PYTEST_DIR/requirements.txt"
)
RESET_SUBMODULES=false
VERBOSE=false
NON_REPRODUCIBLE=false
for arg in "$@"; do
    case $arg in
    --reset-submodules)
        RESET_SUBMODULES=true
        shift
        ;;
    --verbose)
        VERBOSE=true
        ;;
    --non-reproducible)
        NON_REPRODUCIBLE=true
        ;;
    *)
        printf "\nError: Unknown argument: %s, $arg\n"
        exit 1
        ;;
    esac
done

# optional: reset submodules
if [ $RESET_SUBMODULES == true ]; then
    printf "\nResetting submodules"
    if ! log_output git submodule foreach --recursive git reset --hard; then
        echo "Error updating submodule"
        exit 1
    fi
    if ! log_output git submodule foreach --recursive git clean -fdx; then
        echo "Error updating submodule"
        exit 1
    fi
    if ! log_output git submodule update --init --recursive --force; then
        echo "Error updating submodule"
        exit 1
    fi
fi

printf "\nBuilding nearcore"
if ! log_output bash -c "cd '$LIB_DIR/nearcore' && cargo build --quiet --color=always -p neard --release"; then
    echo "Cargo failed to complete nearcore compilation"
    exit 1
fi

printf "\nBuilding main node"
if ! log_output bash -c "cd '$GIT_ROOT' && cargo build --quiet --color=always -p mpc-node --release --features=network-hardship-simulation"; then
    echo "Cargo failed to complete mpc node compilation:"
    exit 1
fi

printf "\nBuilding backup cli"
if ! log_output bash -c "cd '$GIT_ROOT' && cargo build --quiet --color=always -p backup-cli --release"; then
    echo "Cargo failed to complete backup cli compilation:"
    exit 1
fi

printf "\nChecking if virtual environment exists"
if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual enviroment not found. Creating new one."
    cd "$PYTEST_DIR" || {
        echo "Error: Directory $PYTEST_DIR not found"
        exit 1
    }
    if ! log_output python3 -m venv venv; then
        echo "Failed to create virtualenv"
    fi
fi

printf "\nActivating virtual environment."
if ! source "$VENV_DIR/bin/activate"; then
    echo "Error: could not activate virtual environment. $VENV_DIR/bin/activate"
    exit 1
fi

printf "\nInstalling requirements"
for req in "${REQ_DIRS[@]}"; do
    printf '\nInstalling requirement: %s' "$req"
    if ! log_output pip install -r "$req"; then
        echo "Error: Failed to install requirements."
        exit 1
    fi
done

printf "\nExecuting tests"
if ! cd "$PYTEST_DIR"; then
    printf '\nFailed to change directory to  %s', "$PYTEST_DIR"
    exit 1
fi
# Add -s flag if verbose is enabled
PYTEST_FLAGS=""
if $VERBOSE; then
    PYTEST_FLAGS+=" -s"
    printf "\nVerbose mode activated. Adding -s flag to pytest.\n"
fi

if $NON_REPRODUCIBLE; then
    PYTEST_FLAGS+=" --non-reproducible"
fi

# set the NEAR config ensuring that the release version of nearcore is run.
export NEAR_PYTEST_CONFIG="config.json"

if ! log_output pytest "$PYTEST_FLAGS"; then
    printf '\nError: one or more tests failed. Check output.log for details.\n'
    exit 1
else
    printf '\nSuccess.\n'
fi
