#!/bin/bash

# -------------------------------------------------------------------
# Script Name: exec_pytest.sh
# Description: Compiles nearcore, smart contract and mpc node,
#              activates a virtual environment with the required python dependencies,
#              saves output to `output.log`.
#
# Usage:
# - Run the script with optional flags:
#   --reset-submodules : Resets git submodules.
#   --verbose          : Enables detailed log output.
#
# Example:
#   bash exec_pytest.sh --reset-submodules --verbose
#
# Requirements:
# - bash
# - Git
# - Python 3 with venv module
#
# -------------------------------------------------------------------

TEST_FILES=(tests/*.py)
#TEST_FILES=(
#    "pytest.tests.index_signature_request"
#    "pytest.tests.update_test"
#)
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
#REQ_DIR="$LIB_DIR/nearcore/pytest/requirements.txt"

REQ_DIRS=(
    #"$LIB_DIR/nearcore/pytest/requirements.txt"
    "$PYTEST_DIR/requirements.txt"
    # Add more test requirement files here
)
RESET_SUBMODULES=false
VERBOSE=false
for arg in "$@"; do
    case $arg in
    --reset-submodules)
        RESET_SUBMODULES=true
        shift
        ;;
    --verbose)
        VERBOSE=true
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
if ! log_output bash -c "cd '$LIB_DIR/nearcore' && cargo build --quiet --color=always -p neard"; then
    echo "Cargo failed to complete nearcore compilation"
    exit 1
fi

printf "\nBuilding contract"
if ! log_output bash -c "cd '$LIB_DIR/chain-signatures' && cargo build --quiet --color=always -p mpc-contract --target=wasm32-unknown-unknown --release"; then
    echo "Cargo failed to compile contract"
    exit 1
fi

printf "\nCopying contract"
if ! log_output bash -c "mkdir -p '$LIB_DIR/chain-signatures/res' && cp '$LIB_DIR/chain-signatures/target/wasm32-unknown-unknown/release/mpc_contract.wasm' '$LIB_DIR/chain-signatures/res/mpc_contract.wasm'"; then
    echo "Failed to copy the contract"
    exit 1
fi

printf "\nBuilding main node"
if ! log_output bash -c "cd '$GIT_ROOT' && cargo build --quiet --color=always -p mpc-node --release"; then
    echo "Cargo failed to complete mpc node compilation:"
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
for test_file in "${TEST_FILES[@]}"; do
    printf '\nRunning test: %s' "$PYTEST_DIR/$test_file"
    if ! log_output python "$PYTEST_DIR/$test_file"; then
        #if ! log_output python -m "$test_file"; then
        printf '\nError: Test %s failed.' "$test_file"
        exit 1
    else
        printf '\nSuccess: Test %s\n' "$test_file"
    fi
done
