# How to run the python test

Simply run `exec_pytest.sh` (optinal flag `--verbose` and `--reset-submodules`) or execute the steps below with the current directory at root of the mpc git repo.

## Run tests with pytest
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

# build the main node
cd ../.. && cargo build -p mpc-node --release --features=network-hardship-simulation,tee
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
pytest # -v -s optional flags for verbosity and -m "not slow" to skip slow tests
```

Run individual tests with e.g. `pytest tests/test_contract_update.py::test_code_update`
