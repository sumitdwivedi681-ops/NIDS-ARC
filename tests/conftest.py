"""
Pytest configuration and safety overrides.
"""

import sys
from types import ModuleType

# Prevent unstable pyarrow C-extension on Python 3.14 Windows from throwing access violation
dummy_pa = ModuleType("pyarrow")
dummy_pa.__version__ = "18.0.0"

class _DummyType:
    pass

dummy_pa.Table = _DummyType
dummy_pa.RecordBatch = _DummyType
dummy_pa.Array = _DummyType
dummy_pa.ChunkedArray = _DummyType
sys.modules["pyarrow"] = dummy_pa
