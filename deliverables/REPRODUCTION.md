# Reproduction Guide: eBPF-Based Fingerprinting of I/O-Induced Application Stalls

This document provides exact, end-to-end instructions for reproducing the experiments, generating the classification tables, creating the figures, and compiling the IEEE research paper.

---

## 1. Prerequisites and Environment Setup

### 1.1 Target Hardware & OS Requirements
- **OS**: Linux kernel version 5.15 or newer with eBPF support enabled (recommended: Kali Linux 2024.x or Ubuntu 22.04 LTS / 24.04 LTS inside VirtualBox VM).
- **Architecture**: x86_64
- **Privileges**: Root privileges (`sudo`) or `CAP_BPF` / `CAP_SYS_ADMIN` capability.
- **Hardware**: Minimum 4 CPU cores, 4 GB RAM, and 10 GB disk space.

### 1.2 Package Dependencies
Install the required kernel headers, BCC compilers, and Python packages:

```bash
# On Debian/Ubuntu/Kali:
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) \
    bpfcc-tools python3-bpfcc python3-pip python3-dev texlive-latex-base texlive-latex-extra

# Install project Python requirements:
pip install -r requirements.txt
```

---

## 2. Step-by-Step Reproduction Workflow

### Step 1: Preflight Environment Inspection
Verify that kernel tracepoints, headers, and privileges are ready:

```bash
python scripts/check_environment.py
```
*Expected output*: A diagnostic summary saved to `results/environment_manifest.json` indicating `can_run_real_ebpf: true`.

### Step 2: Execute Smoke Test
Run the end-to-end smoke test verifying event schemas, correlation, classifier rules, and live BPF attachment:

```bash
sudo python scripts/smoke_test.py
```
*Expected output*: All 6 pipeline stages report success, with events emitted and decoded from kernel perf buffers.

### Step 3: Run Unit Test Suite
Run the test suite across all modules:

```bash
pytest
```
*Expected output*: All 26+ unit and regression tests pass.

### Step 4: Execute Full Benchmark & Observability Matrix
Run the reproducible experiment matrix across all 5 workload conditions (CPU, Read, Write, Sched-Contention, Sleep) and 3 concurrency levels (1, 2, 4 workers) with 3 repetitions:

```bash
# Run full experimental matrix with real eBPF tracing:
sudo python scripts/run_experiments.py --profile full

# Or for a rapid validation run:
sudo python scripts/run_experiments.py --profile quick
```
*Expected output locations* (`results/run_<timestamp>_<profile>/`):
- `raw_events.jsonl`: Complete, unfiltered eBPF kernel event stream.
- `workload_runs.csv`: Operation boundaries, PIDs, and ground-truth intervention labels.
- `features.csv`: Extracted quantitative feature matrix across all workload windows.
- `predictions.csv`: Model predictions across fused classifier and single-source baselines.
- `test_predictions.csv`: Strictly held-out test split predictions for the decision tree.
- `baseline_comparison.csv`: Comparative evaluation matrix across all models.
- `metrics.json`: Detailed classification scores, Macro-F1, per-class F1, and probe overhead.

### Step 5: Run Extended Ablations
Execute the multi-dimensional ablation study (telemetry layers, time-window sizes, and block attribution):

```bash
python scripts/run_ablations.py results/run_<timestamp>_<profile>/features.csv
```
*Expected output*: `results/run_<timestamp>_<profile>/ablation_study.csv` summarizing performance drops under ablated conditions.

### Step 6: Generate Figures & Report Tables
Generate publication-ready figures and LaTeX tables directly from measured experimental data:

```bash
# Generate figures (confusion matrix, ROC, overhead bars):
python scripts/generate_figures.py results/run_<timestamp>_<profile>

# Generate LaTeX tables and macros for the paper:
python scripts/generate_report_data.py results/run_<timestamp>_<profile> report/
```
*Expected output*:
- `report/figures/confusion_matrix.png`
- `report/figures/overhead_comparison.png`
- `report/tables/baseline_table.tex`
- `report/tables/overhead_table.tex`
- `report/macros.tex`

### Step 7: Compile Research Report PDF
Compile the IEEE-format short paper:

```bash
cd report
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```
*Expected output*: `report/main.pdf` compiled cleanly without missing references or unresolved macros.

---

## 3. Package Deliverables Verification
To regenerate all project submission archives:

```bash
python scripts/package_submission.py
```
This generates:
- `deliverables/report-source.zip`: LaTeX paper sources, BibTeX, figures, and tables.
- `deliverables/project-source.zip`: Complete, clean source code, tests, and configurations.
- `deliverables/REPRODUCTION.md`: This execution guide.
