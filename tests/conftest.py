"""
Pytest configuration and environment fixtures.
"""

import sys
from pathlib import Path

# Ensure src and project root are always in sys.path during test execution
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"

for p in [str(SRC_DIR), str(PROJECT_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)
