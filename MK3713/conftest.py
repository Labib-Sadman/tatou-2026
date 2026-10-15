"""Make `src/` importable for the test suite.

Without this the tests only run when PYTHONPATH is set by hand. It also
makes mutation testing work: mutmut copies the tree into mutants/, where
only the mutated file is present, so the original src/ is appended as a
fallback for sibling modules. Order matters — the mutated copy must win.
"""
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent   # .../server  (or .../mutants)

primary = _root / "src"
if primary.is_dir() and str(primary) not in sys.path:
    sys.path.insert(0, str(primary))             # mutated copy takes priority

fallback = _root.parent / "src"
if fallback.is_dir() and str(fallback) not in sys.path:
    sys.path.append(str(fallback))               # siblings not copied by mutmut
