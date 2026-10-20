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
   - **5 Workload Types**: CPU-bound, Sequential File Read, Synchronous File Write, Scheduler Contention, Intentional Sleep Control.
   - **3 Concurrency Levels**: 1, 2, and 4 worker processes.
   - **Repeated Trials**: 3 to 5 independent repetitions per cell.
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
# 1. Environment preflight
python3 scripts/check_environment.py

# 2. Smoke test
python3 scripts/smoke_test.py

# 3. Full evaluation run
sudo python3 scripts/run_experiments.py --profile full

# 4. Generate figures
python3 scripts/generate_figures.py results/run_<timestamp>_full

# 5. Export LaTeX tables and compile report
python3 scripts/generate_report_data.py results/run_<timestamp>_full report
cd report && pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex
```
