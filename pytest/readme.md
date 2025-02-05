# How to run the python test

Simply run `exec_pytest.sh` (optinal flag `--verbose` and `--reset-submodules`) or execute the steps below with the current directory at root of the mpc git repo.

## Run tests with python
1. Ensure submodules are clean and point to the correct commit. Use the following commands at your own risk:
```bash
git submodule foreach --recursive git reset --hard
git submodule foreach --recursive git clean -fdx
git submodule update --init --recursive --force
```

2. Build nearcore and main node:
```bash
# build nearcore:
cd libs/nearcore && cargo build -p neard --release

# build the contract:
cd ../chain-signatures && cargo build -p mpc-contract --target=wasm32-unknown-unknown --release

# copy the contract:
mkdir -p res && cd cp target/wasm32-unknown-unknown/release/mpc_contract.wasm chain-signatures/res/mpc_contract.wasm
# build the main node
cd ../.. && cargo build -p mpc-node --release
```

3. Set up virtualenv (optional, but recommended):
```bash
cd pytest && python3 -m venv venv

# activate virtualenv:
source venv/bin/activate

# install requirements:
pip install -r requirements.txt
```

4. Run pytest:
```bash
export NEAR_PYTEST_CONFIG="config.json"
pytest # -v -s optional flags for verbosity
```

