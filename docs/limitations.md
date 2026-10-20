# Threats to Validity, Limitations, and Ethical Safeguards

---

## 1. Scientific & Telemetric Limitations

### A. Temporal Proximity vs. Causality
A core tenet of this research is that **temporal proximity does not prove causality**. An application syscall may execute concurrently with a physical block request dispatch without that block request actually being on the critical path of the syscall. In asynchronous buffered I/O, write syscalls merely dirty kernel page cache pages; background kernel flusher threads (`kworker` / `jbd2`) subsequently issue block I/O requests asynchronously. 

Therefore:
- In synchronous operations (`fsync`, `fdatasync`, `O_DIRECT`), causality between syscall blocking and device I/O completion is physically tied.
- In buffered reads and writes, request-to-syscall matching is inherently an **approximate window-level association**.
- The classifier treats absence of block-layer evidence during long buffered syscalls as **indeterminate / ambiguous** rather than fabricating causality.

### B. Virtualization & VirtualBox Artifacts
Executing benchmarks inside an Oracle VirtualBox guest introduces two specific confounding factors:
1. **Hypervisor Scheduling Delay**: If host CPU cores are oversubscribed, virtual CPUs (vCPUs) may experience "steal time" that is not fully accounted for by guest kernel scheduler runqueues.
2. **Virtual Disk Host Caching**: The guest OS communicates with a virtual SATA/NVMe controller whose backing image is cached in the host operating system's RAM, potentially reducing true physical spindle or flash latencies.

### C. Kernel Tracepoint Portability Boundaries
Linux tracepoint arguments evolve between major kernel releases (e.g. Linux 4.x vs 5.x vs 6.x). Tracepoint arguments such as `args->bytes` vs `args->nr_sector * 512` in `block_rq_issue` must be verified via `format` files in tracefs.

---

## 2. Ethical Safeguards & Privacy Protections

1. **Zero Payload Logging**:
   The eBPF collector traces only event metadata: timestamps, syscall identifiers, return codes, byte counts, and scheduler task transitions. At no point are file contents, disk blocks, socket payloads, or memory buffers copied or stored.
2. **Task-Scoping Integrity**:
   BPF hash maps enforce that syscall and scheduler tracing hooks filter exclusively on benchmark process IDs, preventing surveillance or logging of unrelated host/guest tasks.
3. **Non-Destructive Workloads**:
   Workloads operate strictly within designated temporary user directories (`data/temp_workload_files/`). No raw block devices (`/dev/sd*`) or destructive cache-clearing commands (`drop_caches`) are ever invoked.
