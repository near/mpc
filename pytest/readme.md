# How to run the python test

Simply run `exec_pytest.sh` (optional flag `--verbose` and `--reset-submodules`) or execute the steps below with the current directory at root of the mpc git repo.

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
   ```

   ```bash
   # build the main node
   cd ../.. && cargo build -p mpc-node --release --features=network-hardship-simulation
   ```

3. Set up virtualenv (optional, but recommended):

   ```bash
   cd pytest && python3 -m venv venv
   ```

   Activate virtualenv:

   ```bash
   source venv/bin/activate
   ```

   Install requirements:

   ```bash
   pip install -r requirements.txt
   ```

4. Install docker and cargo-near. For the latter:
   ```bash
   cargo install cargo-near --locked
   ```

This is only needed if using reproducible builds for the contract, which is
enabled by default.

5. Run pytest:

   ```bash
   pytest # -v -s optional flags for verbosity and -m "not slow" to skip slow tests
   ```

   In case you run into docker permission issues, make sure your user is part of the docker group and the docker daemon is running, c.f. [docker docs](https://docs.docker.com/engine/install/linux-postinstall/).

   To disable the reproducible build of the contract, use:

   ```bash
   pytest --non-reproducible
   ```

   Run individual tests with e.g.:

   ```bash
   pytest --non-reproducible tests/shared_cluster_tests/test_requests.py::test_request_lifecycle
   ```

### Code Style

To automate formatting and avoid excessive bike shedding, we're using
[Black](https://github.com/psf/black) to format Python source code in the pytest directory. It can be
installed from Python Package Index (PyPI) using `pip` tool:

```bash
python3 -m pip install black
```

Once installed, it can be run either on a single file, or a directory for example
with the following command:

```bash
python3 -m black pytest/
```

#### Auto formatting - Editor Integration

For seamless development experience, configure your editor to automatically format code with Black on save. See the [official Black editor integration documentation](https://black.readthedocs.io/en/stable/integrations/editors.html#editor-integration) for setup instructions for your preferred editor.

##### VS Code Setup

Install the Black Formatter extension
Add these settings to your VS Code settings.json:

```json
{
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "[python]": {
    "editor.defaultFormatter": "ms-python.black-formatter"
  }
}
```

Alternatively, use the Command Palette (Ctrl+Shift+P) and search for "Python: Select Formatter" to choose Black as your default formatter.
