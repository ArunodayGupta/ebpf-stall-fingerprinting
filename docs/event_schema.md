# Telemetry Event Schema Specification

Version: **1.0**  
Format: **JSON Lines (`.jsonl`)**  
Primary Timestamp Domain: **Kernel Monotonic Clock (`CLOCK_MONOTONIC`, in nanoseconds)**

---

## 1. Design Principles

1. **Layer Separation**: Captures syscall, scheduler, and block-layer telemetry without conflating or fusing them inside the kernel.
2. **Task Scoping**: Uses in-kernel BPF hash maps to filter telemetry specifically to the monitored target PIDs/TIDs, minimizing tracing probe overhead.
3. **No Private Payload Tracing**: Traces only operational metadata (timestamps, syscall IDs, return codes, byte counts, scheduling delays). Never records file contents, memory buffers, or user credentials.
4. **Resilience & Loss Accountability**: Records perf buffer lost events (`DROPPED_EVENT_STATS`) and probe attachment diagnostics (`COLLECTOR_DIAGNOSTIC`).

---

## 2. Event Types & Field Definitions

### A. Syscall Events (`SYSCALL_COMPLETE`, `SYSCALL_ENTRY`, `SYSCALL_EXIT`)
Captures application interaction with storage and filesystem APIs.

| Field | Type | Description |
|---|---|---|
| `event_type` | string | `SYSCALL_COMPLETE`, `SYSCALL_ENTRY`, or `SYSCALL_EXIT` |
| `timestamp_ns` | int64 | Monotonic nanoseconds at event occurrence (exit time for complete) |
| `schema_version` | string | Schema version (e.g. `"1.0"`) |
| `pid` | int32 | Process ID |
| `tid` | int32 | Thread ID |
| `comm` | string | Process executable command name |
| `syscall_name` | string | Monitored syscall (`read`, `write`, `fsync`, etc.) |
| `syscall_id` | int32 | Kernel syscall table number |
| `duration_ns` | int64 | Elapsed time spent inside syscall in nanoseconds |
| `ret` | int64 | Syscall return value (bytes read/written, or 0 / error code) |

#### Example:
```json
{
  "event_type": "SYSCALL_COMPLETE",
  "timestamp_ns": 14285920381023,
  "schema_version": "1.0",
  "pid": 4812,
  "tid": 4812,
  "comm": "python3",
  "syscall_name": "fsync",
  "syscall_id": 74,
  "duration_ns": 4210900,
  "ret": 0
}
```

---

### B. Block I/O Events (`BLOCK_RQ_ISSUE`, `BLOCK_RQ_COMPLETE`)
Observes physical device request dispatch and completion at the block layer.

| Field | Type | Description |
|---|---|---|
| `event_type` | string | `BLOCK_RQ_ISSUE` or `BLOCK_RQ_COMPLETE` |
| `timestamp_ns` | int64 | Monotonic timestamp |
| `dev` | uint32 | Device identifier (`MAJOR:MINOR` encoded) |
| `sector` | uint64 | Starting sector number on disk |
| `nr_sector` | uint32 | Number of 512-byte sectors transferred |
| `bytes_count` | uint32 | Total byte length (`nr_sector * 512`) |
| `rwbs` | string | Read/Write/Barrier/Sync flags (e.g. `"R"`, `"WS"`, `"F"`) |
| `pid` | int32 | Submitting PID |
| `error` | int32 | Completion error status (0 for success) |

#### Example:
```json
{
  "event_type": "BLOCK_RQ_COMPLETE",
  "timestamp_ns": 14285924592000,
  "schema_version": "1.0",
  "dev": 2049,
  "sector": 1048576,
  "nr_sector": 128,
  "bytes_count": 65536,
  "rwbs": "R",
  "pid": 4812,
  "error": 0
}
```

---

### C. Scheduler Events (`SCHED_WAKEUP`, `SCHED_SWITCH`)
Measures task runnable delay and off-CPU transitions.

| Field | Type | Description |
|---|---|---|
| `event_type` | string | `SCHED_WAKEUP` or `SCHED_SWITCH` |
| `timestamp_ns` | int64 | Monotonic timestamp |
| `target_pid` | int32 | PID of the monitored task transitioning |
| `prev_pid` | int32 | Outgoing PID on CPU switch |
| `next_pid` | int32 | Incoming PID on CPU switch |
| `prev_state` | int32 | Outgoing task state (`0` = `TASK_RUNNING` / preempted) |
| `is_on_cpu` | bool | `true` if target task is scheduled onto CPU |
| `runnable_delay_ns` | int64 | Measured time the task was runnable waiting for CPU |

#### Example:
```json
{
  "event_type": "SCHED_SWITCH",
  "timestamp_ns": 14285930000000,
  "schema_version": "1.0",
  "target_pid": 4812,
  "prev_pid": 991,
  "next_pid": 4812,
  "prev_state": 0,
  "is_on_cpu": true,
  "runnable_delay_ns": 8504000
}
```

---

### D. Diagnostics and Dropped Event Records

#### `COLLECTOR_DIAGNOSTIC`
```json
{
  "event_type": "COLLECTOR_DIAGNOSTIC",
  "timestamp_ns": 14285900000000,
  "schema_version": "1.0",
  "subsystem": "bpf_probe_attacher",
  "status": "INFO",
  "message": "Attached 12 tracepoints successfully",
  "details": {"probes_attached": 12, "probes_failed": 0}
}
```

#### `DROPPED_EVENT_STATS`
```json
{
  "event_type": "DROPPED_EVENT_STATS",
  "timestamp_ns": 14285950000000,
  "schema_version": "1.0",
  "total_events_emitted": 45120,
  "total_events_lost": 0,
  "loss_rate": 0.0,
  "buffer_type": "perf_buffer"
}
```
