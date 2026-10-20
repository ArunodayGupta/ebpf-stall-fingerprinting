# System Architecture: eBPF Stall Fingerprinting

```
+-----------------------------------------------------------------------------------+
|                               USER SPACE BENCHMARK                                |
|  +------------------+  +-------------------+  +------------------+  +-----------+ |
|  | CPU Workload (A) |  | File Read Seq (B) |  | File Write Sync  |  | Sched (D) | |
|  +------------------+  +-------------------+  +------------------+  +-----------+ |
+------------------------------------------+----------------------------------------+
                                           | Monitored PIDs
                                           v
+-----------------------------------------------------------------------------------+
|                        KERNEL-SIDE eBPF INSTRUMENTATION                            |
|                                                                                   |
|  [tracepoint:syscalls:sys_enter/exit_*]  -->  BPF_HASH(syscall_starts)            |
|  [tracepoint:block:block_rq_issue/comp]  -->  Window-level request accounting     |
|  [tracepoint:sched:sched_wakeup/switch]  -->  BPF_HASH(runnable_starts)           |
|                                                                                   |
|                 +-----------------------------------------------+                 |
|                 |      In-Kernel PID Filter: target_pids        |                 |
|                 +-----------------------+-----------------------+                 |
|                                         | Filtered Events                         |
|                                         v                                         |
|                 +-----------------------------------------------+                 |
|                 |      BPF_PERF_OUTPUT Ring Buffer (64 pages)   |                 |
|                 +-----------------------+-----------------------+                 |
+------------------------------------------|----------------------------------------+
                                           | Polled via BCC ctypes
                                           v
+-----------------------------------------------------------------------------------+
|                       USER-SPACE COLLECTOR & PIPELINE                             |
|                                                                                   |
|  1. Event Stream Serialization   --> raw_events.jsonl                             |
|  2. Event Correlation Engine     --> Non-overlapping Interval Union Algorithm     |
|  3. Quantitative Feature Table   --> features.csv                                 |
|  4. Transparent Rule Classifier  --> predictions.csv + explanations               |
|  5. Single-Source Baselines      --> Feature-isolated comparisons                 |
|  6. Lightweight Decision Tree    --> Grouped train/test evaluation                |
|  7. Evaluation & Metrics Suite   --> Macro-F1, Confusion Matrix, Overhead         |
+-----------------------------------------------------------------------------------+
```

## Architectural Components

1. **In-Kernel Telemetry Collection (`src/stall_fingerprint/bpf_program.py`)**:
   - Compiled via BCC from embedded C code.
   - Attaches strictly to stable kernel tracepoints (`syscalls`, `block`, `sched`).
   - Implements in-kernel filtering using `BPF_HASH(target_pids)` to eliminate tracing overhead on untraced background processes (Craun et al., 2024).

2. **Event Delivery & Loss Accounting (`src/stall_fingerprint/collector.py`)**:
   - Streams events using BCC perf output buffers.
   - Registers a `lost_cb` callback to immediately catch and record buffer overruns (`DROPPED_EVENT_STATS`).

3. **Window Correlation & Interval Union (`src/stall_fingerprint/correlation.py`)**:
   - Correlates asynchronous kernel events with workload operation boundaries.
   - Employs an interval union algorithm to calculate exact non-overlapping durations for syscalls and scheduler delays, preventing duration double-counting.

4. **Multi-Method Classification (`src/stall_fingerprint/classifier_rules.py`, `baselines.py`, `classifier_ml.py`)**:
   - **Fused Rule Classifier**: Transparent, threshold-governed decision tree producing human-interpretable reasoning.
   - **Single-Source Baselines**: Syscall-Only, Block-Only, and Scheduler-Only models enforcing strict feature isolation.
   - **Lightweight Decision Tree**: Interpretable machine learning baseline trained with grouped trial splits.
