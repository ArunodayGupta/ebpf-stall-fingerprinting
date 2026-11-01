"""
Utilities and common helpers for controlled experimental workloads.
"""

import os
import sys
import time
import json
import ctypes
import hashlib
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
    parent_trial_id: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_comm: str = ""
    dropped_events_count: int = 0
    total_events_emitted: int = 0

    def __post_init__(self):
        if not self.parent_trial_id:
            if "_worker_" in self.trial_id:
                self.parent_trial_id = self.trial_id.split("_worker_")[0]
            else:
                self.parent_trial_id = self.trial_id

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

def get_monotonic_ns() -> int:
    """Returns high-resolution monotonic time in nanoseconds matching kernel bpf_ktime_get_ns()."""
    return time.monotonic_ns()

def make_target_comm(identity: str) -> str:
    """Return a stable, short Linux task name for telemetry correlation."""
    digest = hashlib.blake2s(identity.encode("utf-8"), digest_size=6).hexdigest()
    return f"sfp{digest}"[:15]

def set_thread_comm(comm: str) -> None:
    """Set the calling Linux task's comm field (PR_SET_NAME, limited to 15 bytes)."""
    if os.name != "posix" or not hasattr(ctypes, "CDLL"):
        return
    value = comm.encode("utf-8")[:15]
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(15, value, 0, 0, 0) != 0:  # PR_SET_NAME
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

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
