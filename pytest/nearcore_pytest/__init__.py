import sys
from pathlib import Path

# Dynamically add the nearcore/pytest/lib folder to sys.path
LIB_PATH = Path(
    __file__).resolve().parents[2] / "libs" / "nearcore" / "pytest" / "lib"
if str(LIB_PATH) not in sys.path:
    sys.path.insert(0, str(LIB_PATH))

# Debugging output
print(f"LIB_PATH added to sys.path: {LIB_PATH}")
print(f"sys.path contents:\n{sys.path}")
