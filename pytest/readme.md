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
cd ../.. && cargo build -p mpc-node --release --features=network-hardship-simulation
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

### Code Style

To automate formatting and avoid excessive bike shedding, we're using
YAPF to format Python source code in the pytest directory. It can be
installed from Python Package Index (PyPI) using `pip` tool:

    python3 -m pip install yapf

Once installed, it can be run either on a single file, for example
with the following command:

    python3 -m yapf -pi lib/cluster.py

or the entire directory with command as seen below:

    python3 -m yapf -pir .

The `-p` switch enables parallelism and `-i` applies the changes in
place. Without the latter switch the tool will write formatted file
to standard output instead.

The command should be executed in the `pytest` directory so that it’ll
pick up configuration from the `.style.yapf` file.
