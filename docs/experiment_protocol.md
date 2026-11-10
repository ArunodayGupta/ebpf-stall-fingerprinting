# Experimental Protocol & Reproducibility Guide

---

## 1. Experimental Protocol

To ensure rigorous, scientifically reproducible results, all experiments follow this protocol:

1. **Preflight Validation**:
   Run `scripts/check_environment.py` to inspect kernel version, BCC bindings, tracepoint formats, and CPU/memory specifications. Output is logged to `results/environment_manifest.json`.

2. **Unmonitored Control Run**:
   Before attaching any tracing hooks, run unmonitored baseline workloads across all categories to establish the unperturbed ground-truth performance baseline.

3. **Monitored Factorial Run**:
   Execute the full factorial matrix:
   - **5 Workload Types**: CPU-bound, sequential file read, synchronous file write, scheduler contention, and intentional sleep control.
   - Read conditions: 8 MiB and 32 MiB with warm and best-effort cold-cache conditions.
   - Synchronous write conditions: 8 MiB and 32 MiB.
   - **3 Concurrency Levels**: 1, 2, and 4 worker processes.
   - **Repeated Trials**: 2 repetitions in quick mode; 5 in full mode, for every workload, I/O condition, and concurrency level.
   - In-kernel BPF probes actively record syscall, block, and scheduler events.

4. **Telemetry Processing & Feature Extraction**:
   - Correlate raw JSON Lines events with workload operational timestamps.
   - Extract quantitative non-overlapping duration ratios.

5. **Multi-Method Evaluation**:
   - Evaluate Fused Rule-Based Classifier.
   - Evaluate Single-Source Baselines (Syscall-Only, Block-Only, Sched-Only).
   - Evaluate Lightweight Decision Tree using grouped train/test split.

6. **Ablation Studies**:
   - Systematically remove block I/O, scheduler telemetry, or syscall duration features and quantify Macro-F1 degradation.
   - Vary window margin and block-event attribution mode.
7. **Transfer and Cost Evaluation**:
   - Hold out each configured I/O file size from decision-tree training and evaluate on that size.
   - Record MiB/s, p99 operation latency, per-operation process CPU time, dropped-event rate, and monitored/unmonitored duration overhead.
   - Compare measured overhead with the predeclared 10% budget in `config/experiment_config.yaml`.
   - Report absolute blocked-time error only for the controlled sleep workload, whose injected duration is known. This is not storage-stall ground truth.

---

## 2. Execution Profiles

| Parameter | Quick Profile (Smoke/Debug) | Full Profile (Evaluation) |
|---|---|---|
| Concurrency Levels | `[1, 2]` | `[1, 2, 4]` |
| Repetitions | 2 | 5 |
| File Size (I/O) | 8 MB | 32 MB |
| CPU Iterations | 500,000 | 2,000,000 |
| Sleep Duration | 100 ms | 200 ms |
| Contention Workers | 2 | 4 |

---

## 3. Command Execution Sequence

### Inside Kali Linux VM:
```bash
# From the repository root. Install matching kernel headers, BCC, and Python dependencies first.
sudo apt install -y build-essential linux-headers-$(uname -r) bpfcc-tools python3-bpfcc python3-venv python3-pip texlive-latex-base texlive-latex-recommended
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

# 1. Environment preflight
.venv/bin/python scripts/check_environment.py

# 2. Smoke test
sudo .venv/bin/python scripts/smoke_test.py

# 3. Full evaluation run
sudo .venv/bin/python scripts/run_experiments.py --profile full

# 4. Generate figures
.venv/bin/python scripts/generate_figures.py results/run_<timestamp>_full

# 5. Export LaTeX tables and compile report
.venv/bin/python scripts/generate_report_data.py results/run_<timestamp>_full report
(cd report && pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex)
```
