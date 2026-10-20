# Research Methodology: Classification Taxonomy & Signal Fusion

---

## 1. Stall Classification Taxonomy

Every observed operation window $[t_{start}, t_{end}]$ is categorized into one of four mutually exclusive classes:

1. **`io_wait_dominated`**:
   The primary delay is associated with physical storage I/O. Characterized by elevated duration inside storage system calls (`read`, `write`, `fsync`) corroborated by physical block-layer device request activity (`block_rq_issue`, `block_rq_complete`).
2. **`scheduler_wait_dominated`**:
   The task was runnable and ready to execute, but delayed due to CPU runqueue contention. Quantified by `runnable_delay_ns` accumulated from task wakeup or preemption until dispatch onto CPU.
3. **`cpu_syscall_dominated`**:
   The operation is explained primarily by on-CPU computational execution and fast in-memory syscall handling, without significant storage or scheduling latency.
4. **`indeterminate`**:
   Telemetry is absent, corrupt, contradictory, or insufficient (e.g. deliberate sleep delay where task is voluntarily blocked without storage I/O, or cached file reads where syscalls occur without device block requests).

---

## 2. Quantitative Feature Mathematics

Let $W = [t_{start}, t_{end}]$ be an operation window with duration $\Delta t = t_{end} - t_{start}$.

### A. Non-Overlapping Syscall Duration
Let $S = \{(s_i, e_i)\}$ be the set of syscall entry and exit timestamps falling within $W$. The non-overlapping syscall duration is calculated via interval union:
$$T_{sys} = \mu \left( \bigcup_{i} [s_i, e_i] \cap [t_{start}, t_{end}] \right)$$
where $\mu$ denotes the Lebesgue measure on $\mathbb{R}$. The syscall duration ratio is:
$$R_{sys} = \min\left(1.0, \frac{T_{sys}}{\Delta t}\right)$$

### B. Runnable Scheduler Wait Duration
Let $R = \{d_k\}$ be the set of measured runnable delays emitted on `sched_switch` onto CPU for the target task:
$$T_{sched} = \min\left(\Delta t, \sum_k d_k\right)$$
The runnable wait ratio is:
$$R_{sched} = \frac{T_{sched}}{\Delta t}$$

### C. Observed On-CPU Execution & Unobserved Gap
The accounted stall delay is:
$$T_{stall} = \min(\Delta t, T_{sys} + T_{sched})$$
The estimated on-CPU execution duration is:
$$T_{cpu} = \Delta t - T_{stall}$$
The on-CPU ratio is:
$$R_{cpu} = \frac{T_{cpu}}{\Delta t}$$

If the window exhibits zero telemetry events ($N_{sys} = 0, N_{block} = 0, N_{sched} = 0$), the entire duration is classified as unobserved:
$$R_{unobserved} = 1.0, \quad R_{cpu} = 0.0$$

---

## 3. Evaluation Metrics

1. **Macro-F1**: Unweighted mean of F1 scores across classes with non-zero support:
   $$\text{Macro-F1} = \frac{1}{|C|} \sum_{c \in C} F1_c$$
2. **Abstention Rate**: Fraction of samples assigned to `indeterminate`:
   $$\text{Abstention Rate} = \frac{\sum \mathbb{I}(\hat{y} = \text{indeterminate})}{N}$$
3. **Coverage**: $1 - \text{Abstention Rate}$.
4. **Non-Abstained Accuracy**: Accuracy evaluated strictly among samples where the model did not abstain ($\hat{y} \ne \text{indeterminate}$).
5. **Runtime Overhead**:
   $$\text{Overhead \%} = \frac{\bar{T}_{monitored} - \bar{T}_{unmonitored}}{\bar{T}_{unmonitored}} \times 100\%$$
