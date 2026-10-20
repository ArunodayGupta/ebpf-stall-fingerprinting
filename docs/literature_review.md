# Literature Review: eBPF Observability & I/O Stall Attribution

This literature survey contextualizes the research problem: distinguishing whether an application stall is primarily caused by **storage I/O**, **runnable scheduler delay**, or **on-CPU/syscall processing**, while explicitly identifying **indeterminate / ambiguous** cases.

---

## 1. Research Papers & System Contributions

### A. Tracing Overhead and Process Scoping
* **Craun et al., "Eliminating eBPF Tracing Overhead on Untraced Processes" (ACM eBPF '24)** [DOI: `10.1145/3672197.3673431`]  
  * *Problem:* Dynamic tracing via kernel kprobes or global tracepoints historically triggers across all processes on the operating system, forcing untraced background processes to execute trap handlers and incur unneeded CPU overhead.
  * *Key Finding:* In-BPF PID checks reduce data transfer but still incur probe invocation overhead. 
  * *Motivation for our Design:* Demonstrates why in-kernel BPF map filtering (`BPF_HASH(target_pids)`) is mandatory at the earliest tracepoint probe entry, strictly scoping collection to benchmark worker processes.

* **Piotrowski, "Benchmarking Performance Overhead of DTrace on FreeBSD and eBPF on Linux" (AsiaBSDCon 2024)**  
  * *Problem:* Observability tools introduce an observer effect ("probe effect") that alters the very timings they measure.
  * *Key Finding:* Syscall tracing frequency strongly correlates with instruction cache misses and throughput degradation under micro-benchmarks.
  * *Motivation for our Design:* Directly motivates our measurement of both **unmonitored** and **monitored** workloads, computing percentage overhead and tail latency impact (p50, p90, p99).

* **Naas et al., "Dissecting Storage I/O Tracing Overhead of eBPF: A Component-Level Analysis" (CHEOPS '26 / EuroSys)** [DOI: `10.1145/3805687.3806254`]  
  * *Problem:* Modern storage engines operate at microsecond scales, exposing significant bottlenecks when tracing block-layer requests.
  * *Key Finding:* Tracing high-frequency block requests causes ring buffer contention and map update lock overhead.
  * *Motivation for our Design:* Justifies our window-level aggregation strategy and perf buffer sizing (64 pages) to prevent dropped event cascades.

### B. eBPF Memory and Execution Efficiency
* **Liu, Tak, & Wang, "Understanding Performance of eBPF Maps" (ACM eBPF '24)** [DOI: `10.1145/3672197.3673430`]  
  * *Problem:* Hash maps in eBPF can introduce lookup latency and cache eviction penalties when improperly dimensioned.
  * *Motivation for our Design:* Informs the hash table capacity for `syscall_starts` (4096 entries) and `runnable_starts` (4096 entries) to guarantee $O(1)$ constant-time lookup and zero hash bucket collision overhead.

* **Mao et al., "Merlin: Multi-tier Optimization of eBPF Code for Performance and Compactness" (ASPLOS '24)** [DOI: `10.1145/3620666.3651387`]  
  * *Key Finding:* Compact BPF bytecode reduces verifier complexity and runtime latency.
  * *Motivation for our Design:* Keeps our kernel C handlers streamlined, offloading interval union and feature extraction logic to user space.

### C. Off-CPU Analysis and Latency Attribution
* **Brendan Gregg, "BPF Performance Tools" (Addison-Wesley, 2019)**  
  * *Core Concept:* Off-CPU analysis tracks time tasks spend off CPU. Gregg emphasizes that off-CPU time consists of two fundamentally distinct states:
    1. *Voluntary or involuntary blocking* (task enters a sleep/wait queue, `prev_state != 0`)
    2. *Runnable waiting* (task is ready to execute in runqueue but delayed waiting for CPU, `prev_state == 0`)
  * *Motivation for our Design:* Directly defines our scheduler transition tracking (`sched_wakeup` to `sched_switch` onto CPU) to accurately quantify `runnable_delay_ns` without confusing voluntary sleep with scheduler starvation.

* **Curtsinger & Berger, "Coz: Finding Code that Counts with Causal Profiling" (SOSP '15)** [DOI: `10.1145/2815400.2815409`]  
  * *Core Insight:* Proximity does not imply causality; optimizing an arbitrary stall does not improve end-to-end latency unless that stall lies on the critical execution path.
  * *Scientific Constraint in our Project:* Temporal proximity between a block I/O request and a slow syscall does not prove device causation. We explicitly formulate this in our correlation engine and establish an **abstention class (`indeterminate`)** when evidence is inconclusive.

---

## 2. Tested Research Hypotheses

* **Hypothesis 1 (H1):** Fusing syscall, block-layer, and scheduler evidence classifies controlled application stalls more accurately than any single-layer signal baseline (Syscall-only, Block-only, or Sched-only).
* **Hypothesis 2 (H2):** Formulating an explicit abstention class (`indeterminate`) prevents high-confidence misclassifications under ambiguous conditions (such as cached file reads or deliberate application sleep).
