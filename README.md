# eBPF-Based Fingerprinting of I/O-Induced Application Stalls

**Operating Systems Research Project — Assignment 3**  
*Separate storage waits from scheduler and application delays using multi-layer Linux kernel telemetry.*

---

## 1. Project Overview & Scientific Motivation

When applications suffer from tail latency spikes or transient execution stalls, identifying whether the bottleneck originates from **storage I/O**, **runnable scheduler delay**, or **CPU/syscall processing** is notoriously challenging. A single end-to-end latency metric aggregates diverse operating system phenomena. Furthermore, treating a nearby block request as the definitive cause of a slow system call introduces a severe correlational fallacy due to filesystem caching, readahead, and asynchronous writeback.

This project implements an end-to-end, reproducible research framework using **eBPF (Extended Berkeley Packet Filter)** on Linux to collect and fuse:
1. **System Call Telemetry**: Tracing entry, exit, and elapsed durations of storage calls (`read`, `pread64`, `write`, `pwrite64`, `fsync`, `fdatasync`).
2. **Block-Layer Telemetry**: Monitoring physical device request issues (`block_rq_issue`) and completions (`block_rq_complete`).
3. **Scheduler Telemetry**: Measuring task wakeups (`sched_wakeup`), preemptions, and context switches (`sched_switch`) to quantify time spent runnable waiting for CPU time.

### The Four Target Categories
- `io_wait_dominated`: Stalls predominantly explained by storage waiting.
- `scheduler_wait_dominated`: Stalls caused by runnable delay due to CPU runqueue contention.
- `cpu_syscall_dominated`: Delay explained by active on-CPU computation and fast in-memory syscall handling.
- `indeterminate`: Explicit abstention class when telemetry is missing, contradictory, or insufficient (e.g. voluntary sleep delays or ambiguous cached reads).

---

## 2. Repository Structure

```
ebpf-stall-fingerprinting/
├── README.md                          # Primary project documentation and execution guide
├── requirements.txt                   # Python library dependencies
├── pyproject.toml                     # Python package and pytest configuration
├── .gitignore                         # Version control exclusions
├── config/
│   └── experiment_config.yaml         # Centralized workload, threshold, and collector config
├── docs/
│   ├── architecture.md                # System component diagram and dataflow
│   ├── environment_setup.md           # VirtualBox Kali VM setup and prerequisites
│   ├── event_schema.md                # Versioned JSON Lines telemetry schema specification
│   ├── experiment_protocol.md         # Controlled experimental protocol and run matrix
│   ├── methodology.md                 # Mathematical formulations and classification logic
│   ├── limitations.md                 # Threats to validity, causality bounds, and privacy
│   └── literature_review.md           # Survey of 9 verified peer-reviewed papers
├── src/
│   └── stall_fingerprint/
│       ├── __init__.py                # Package initialization
│       ├── bpf_program.py             # Embedded BPF C source code and ctypes definitions
│       ├── collector.py               # BCC lifecycle manager, perf-buffer poller, drop tracker
│       ├── event_schema.py            # Event dataclasses, JSON Lines parser, and serializer
│       ├── correlation.py             # Event correlation and interval union engine
│       ├── feature_extraction.py      # Quantitative feature extractor (non-overlapping ratios)
│       ├── classifier_rules.py        # Transparent rule classifier with structured explanations
│       ├── classifier_ml.py           # Grouped train/test lightweight Decision Tree classifier
│       ├── baselines.py               # Single-source baselines (Syscall, Block, Sched-only)
│       ├── evaluation.py              # Macro-F1, per-class PR, confusion matrix, overhead
│       └── workload_supervisor.py     # Multi-concurrency workload dispatcher and coordinator
├── workloads/
│   ├── cpu_workload.py                # Workload A: Bounded SHA-256 loop (no file I/O)
│   ├── read_workload.py               # Workload B: Sequential file read with fadvise hints
│   ├── write_workload.py              # Workload C: Bounded writes with explicit fsync
│   ├── scheduler_contention.py        # Workload D: Target task with competing CPU stress workers
│   ├── sleep_control.py               # Negative Control: Explicit voluntary sleep delay
│   └── workload_utils.py              # Monotonic timing, metadata tracking, isolated cleanup
├── scripts/
│   ├── check_environment.py           # Environment preflight checker and manifest generator
│   ├── smoke_test.py                  # End-to-end 5-stage verification smoke test
│   ├── run_experiments.py             # Factorial experimental runner (quick and full profiles)
│   ├── run_ablations.py               # Telemetry layer ablation study runner
│   ├── generate_figures.py            # Publication-quality matplotlib/seaborn figure generator
│   ├── generate_report_data.py        # LaTeX table and macro exporter for paper
│   ├── package_submission.py          # Deliverables packager and integrity validator
│   └── package_submission.sh          # Linux shell packaging script
├── tests/
│   ├── conftest.py                    # Pytest environment fixtures
│   ├── test_event_schema.py           # Schema serialization and corruption tolerance tests
│   ├── test_correlation.py            # Interval union and window matching tests
│   ├── test_feature_extraction.py     # Quantitative ratio bounds and accounting tests
│   ├── test_classifier_rules.py       # Rule classification and explanation tests
│   ├── test_baselines.py              # Single-source baseline feature isolation tests
│   ├── test_evaluation.py             # Macro-F1, confusion matrix, overhead tests
│   └── test_data_validation.py        # ML data sufficiency and grouped-split leakage tests
├── report/
│   ├── main.tex                       # 6-page IEEE conference paper (LaTeX source)
│   ├── references.bib                 # Verified BibTeX bibliography
│   ├── macros.tex                     # Dynamic numerical metrics definitions
│   ├── tables/                        # Exported LaTeX tables
│   └── figures/                       # Generated report plots
├── data/
│   └── .gitkeep                       # Isolated temporary workload directory
├── results/
│   ├── .gitkeep                       # Output run logs and manifests
│   └── environment_manifest.json      # Host preflight diagnostic record
└── deliverables/                      # Generated ZIP archives (report & project source)
```

---

## 3. Environment Prerequisites & Kali Linux VM Setup

The target execution environment is **Kali Linux inside Oracle VirtualBox**:

### Host VirtualBox Configuration:
- **vCPUs**: At least 2 allocated (4 recommended for scheduler contention experiments).
- **RAM**: 2048 MB minimum (4096 MB recommended).
- **Network**: NAT with Port Forwarding (Host Port `2222` $\rightarrow$ Guest Port `22`).
- **Shared Folder**: Mount repository from host to guest (e.g. `/mnt/ebpf_project`).

### Inside the Kali Linux VM:
```bash
# 1. Update apt repositories
sudo apt update

# 2. Install matching kernel headers (critical for BCC compilation)
sudo apt install -y linux-headers-$(uname -r)

# 3. Install BCC, Clang, LLVM, and Python BCC bindings
sudo apt install -y bpfcc-tools python3-bpfcc libbpf-dev clang llvm

# 4. Install Python dependencies
sudo apt install -y python3-pip python3-numpy python3-pandas python3-sklearn \
                    python3-scipy python3-matplotlib python3-seaborn \
                    python3-yaml python3-psutil python3-pytest

# 5. (Optional) LaTeX distribution for report compilation
sudo apt install -y texlive-latex-base texlive-latex-recommended texlive-fonts-recommended
```

---

## 4. Execution Workflow

### Step 1: Run Environment Preflight Checker
```bash
python3 scripts/check_environment.py
```
*Inspects kernel headers, BCC availability, tracepoint formats, CPU cores, and emits `results/environment_manifest.json`.*

### Step 2: Run Unit Test Suite
```bash
python3 -m pytest tests -v
```
*Executes all 26 unit tests covering schema validation, interval union arithmetic, feature isolation, rule logic, and ML grouped splits.*

### Step 3: Run Smoke Test
```bash
python3 scripts/smoke_test.py
```
*Validates the full 5-stage pipeline: workload execution $\rightarrow$ event logging $\rightarrow$ correlation $\rightarrow$ feature extraction $\rightarrow$ rule classification.*

### Step 4: Run Experimental Suite
Execute the factorial evaluation matrix across workloads, concurrency levels, and repeated trials:
```bash
# Quick profile (for debugging/smoke runs):
sudo python3 scripts/run_experiments.py --profile quick

# Full evaluation profile (required for complete research submission):
sudo python3 scripts/run_experiments.py --profile full
```
Outputs are saved to `results/run_YYYYMMDD_HHMMSS_full/`:
- `workload_runs.csv`: Operation timestamps and ground truth labels.
- `raw_events.jsonl`: Complete eBPF event stream.
- `features.csv`: Extracted quantitative feature vectors.
- `predictions.csv`: Predictions from Fused, Baselines, and ML models.
- `metrics.json`: Macro-F1, per-class PR, confusion matrices, and overhead.
- `baseline_comparison.csv`: Comparative summary table.

### Step 5: Run Ablation Study
```bash
python3 scripts/run_ablations.py results/run_<timestamp>_full/features.csv
```
*Evaluates the contribution of individual layers by systematically ablating Block I/O, Scheduler, and Syscall signals.*

### Step 6: Generate Publication Figures
```bash
python3 scripts/generate_figures.py results/run_<timestamp>_full
```
*Generates baseline comparisons, confusion matrices, overhead charts, and runnable wait boxplots in `figures/`.*

### Step 7: Export LaTeX Tables and Compile Report
```bash
python3 scripts/generate_report_data.py results/run_<timestamp>_full report
cd report
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

### Step 8: Package Submission Deliverables
```bash
python3 scripts/package_submission.py
```
*Validates repository integrity and produces:*
- `deliverables/report-source.zip`
- `deliverables/project-source.zip`

---

## 5. Troubleshooting Common Issues

1. **`BCC is not available in current environment`**:
   - Cause: Running on Windows or Linux without `python3-bpfcc`.
   - Remedy: Run inside Kali Linux with `sudo apt install -y bpfcc-tools python3-bpfcc`.
2. **`Kernel headers for ... not found`**:
   - Cause: Linux kernel headers do not match active kernel version.
   - Remedy: `sudo apt install -y linux-headers-$(uname -r)`.
3. **`Root privileges (EUID 0) required`**:
   - Cause: Loading eBPF tracing programs requires `CAP_BPF` / root privileges.
   - Remedy: Prefix experiment execution commands with `sudo`.
4. **`Neither /sys/kernel/tracing nor /sys/kernel/debug/tracing is mounted`**:
   - Remedy: `sudo mount -t tracefs nodev /sys/kernel/tracing`.
