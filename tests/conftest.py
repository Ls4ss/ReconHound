"""Pytest configuration and environment setup."""

import os
import sys
from pathlib import Path

# Add project root and reconexec to sys.path
_root = Path(__file__).resolve().parent.parent
_reconexec_cli = _root / "reconexec"

for path in [_reconexec_cli, _root]:
    p_str = str(path)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)
