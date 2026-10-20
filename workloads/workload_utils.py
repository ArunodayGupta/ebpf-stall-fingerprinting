"""
Utilities and common helpers for controlled experimental workloads.
"""

import os
import sys
import time
import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Any, Optional

@dataclass
class WorkloadOperationRecord:
    trial_id: str
    workload_type: str
    operation_id: int
    pid: int
    tid: int
    start_ns: int
    end_ns: int
    duration_ns: int
    intervention_label: str
    expected_label: str
    concurrency: int = 1
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

def get_monotonic_ns() -> int:
    """Returns high-resolution monotonic time in nanoseconds matching kernel bpf_ktime_get_ns()."""
    return time.monotonic_ns()

def isolate_test_directory(base_dir: str = "data") -> Path:
    """Creates a dedicated, isolated directory for temporary workload files."""
    p = Path(base_dir).resolve() / "temp_workload_files"
    p.mkdir(parents=True, exist_ok=True)
    return p

def cleanup_file(path: Path):
    """Safely removes an experimental data file if it exists."""
    try:
        if path.exists() and path.is_file():
            path.unlink()
    except Exception as e:
        sys.stderr.write(f"Warning: failed to remove temporary file {path}: {e}\n")

def apply_cold_cache_advice(file_descriptor: int):
    """
    Best-effort cache eviction advice using POSIX_FADV_DONTNEED where supported.
    Documents the limitation that this is advisory only and not a guarantee of a cache miss.
    """
    try:
        if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_DONTNEED"):
            os.posix_fadvise(file_descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
            return True
    except Exception:
        pass
    return False
