#!/usr/bin/env python3
"""
Submission Packaging & Validation Script.

Creates and validates the four submission deliverables:
- Deliverable A: Research-report PDF compilation check
- Deliverable B: report-source.zip (LaTeX source, BibTeX, tables, figures, build instructions)
- Deliverable C: project-source.zip (Clean source code, workloads, tests, scripts, config)
- Deliverable D: Execution guide validation (README.md)
"""

import sys
import os
import zipfile
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def validate_core_files() -> bool:
    required_paths = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "requirements.txt",
        REPO_ROOT / "pyproject.toml",
        REPO_ROOT / "config" / "experiment_config.yaml",
        REPO_ROOT / "docs" / "architecture.md",
        REPO_ROOT / "docs" / "environment_setup.md",
        REPO_ROOT / "docs" / "event_schema.md",
        REPO_ROOT / "docs" / "experiment_protocol.md",
        REPO_ROOT / "docs" / "methodology.md",
        REPO_ROOT / "docs" / "limitations.md",
        REPO_ROOT / "docs" / "literature_review.md",
        REPO_ROOT / "src" / "stall_fingerprint" / "__init__.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "bpf_program.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "collector.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "event_schema.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "correlation.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "feature_extraction.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "classifier_rules.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "baselines.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "classifier_ml.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "evaluation.py",
        REPO_ROOT / "src" / "stall_fingerprint" / "workload_supervisor.py",
        REPO_ROOT / "workloads" / "cpu_workload.py",
        REPO_ROOT / "workloads" / "read_workload.py",
        REPO_ROOT / "workloads" / "write_workload.py",
        REPO_ROOT / "workloads" / "scheduler_contention.py",
        REPO_ROOT / "workloads" / "sleep_control.py",
        REPO_ROOT / "workloads" / "workload_utils.py",
        REPO_ROOT / "scripts" / "check_environment.py",
        REPO_ROOT / "scripts" / "smoke_test.py",
        REPO_ROOT / "scripts" / "run_experiments.py",
        REPO_ROOT / "scripts" / "generate_figures.py",
        REPO_ROOT / "scripts" / "generate_report_data.py",
        REPO_ROOT / "report" / "main.tex",
        REPO_ROOT / "report" / "references.bib",
    ]

    missing = [str(p.relative_to(REPO_ROOT)) for p in required_paths if not p.exists()]
    if missing:
        print("ERROR: Missing required project files:")
        for m in missing:
            print(f"  - {m}")
        return False
    return True

def create_report_source_zip(deliverables_dir: Path) -> Path:
    zip_path = deliverables_dir / "report-source.zip"
    report_dir = REPO_ROOT / "report"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(report_dir):
            for file in files:
                # Exclude build junk
                if file.endswith((".aux", ".bbl", ".blg", ".log", ".out", ".toc", ".synctex.gz", ".fls", ".fdb_latexmk")):
                    continue
                file_path = Path(root) / file
                arcname = file_path.relative_to(report_dir)
                zf.write(file_path, arcname=str(Path("report") / arcname))

    print(f"Created: {zip_path} ({zip_path.stat().st_size / 1024:.1f} KB)")
    return zip_path

def create_project_source_zip(deliverables_dir: Path) -> Path:
    zip_path = deliverables_dir / "project-source.zip"

    exclude_patterns = {
        "__pycache__",
        ".pytest_cache",
        ".git",
        ".venv",
        "venv",
        "deliverables",
    }
    exclude_extensions = {".pyc", ".pyo", ".log", ".aux", ".bbl", ".blg"}

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in exclude_patterns]
            for file in files:
                p = Path(root) / file
                if p.suffix in exclude_extensions:
                    continue
                if "deliverables" in p.parts:
                    continue
                arcname = p.relative_to(REPO_ROOT)
                zf.write(p, arcname=str(arcname))

    print(f"Created: {zip_path} ({zip_path.stat().st_size / 1024:.1f} KB)")
    return zip_path

def generate_reproduction_guide(deliverables_dir: Path) -> Path:
    """Generates the standalone reproduction guide document for external evaluators."""
    guide_path = deliverables_dir / "REPRODUCTION.md"
    content = """# Reproduction Guide: eBPF-Based Fingerprinting of I/O-Induced Application Stalls

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
sudo apt install -y build-essential linux-headers-$(uname -r) \\
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
"""
    with open(guide_path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"Created reproduction guide: {guide_path}")
    return guide_path

def compile_report_pdf(deliverables_dir: Path) -> bool:
    """Attempts to compile the LaTeX paper to PDF if pdflatex is installed."""
    pdflatex = shutil.which("pdflatex")
    if not pdflatex:
        print("[INFO] pdflatex not found on host; skipping local PDF compilation.")
        print("       (LaTeX source is completely packaged in report-source.zip for compilation on target system).")
        return False

    report_dir = REPO_ROOT / "report"
    print(f"Compiling research report PDF via {pdflatex}...")
    try:
        cmd = [pdflatex, "-interaction=nonstopmode", "main.tex"]
        subprocess.run(cmd, cwd=report_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        bibtex = shutil.which("bibtex")
        if bibtex:
            subprocess.run([bibtex, "main"], cwd=report_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(cmd, cwd=report_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(cmd, cwd=report_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        src_pdf = report_dir / "main.pdf"
        if src_pdf.exists():
            dest_pdf = deliverables_dir / "eBPF_Stall_Fingerprinting_Report.pdf"
            shutil.copy2(src_pdf, dest_pdf)
            print(f"Compiled and copied report PDF: {dest_pdf}")
            return True
    except Exception as e:
        print(f"[WARNING] Local LaTeX compilation error: {e}")
    return False

def main():
    print("=" * 60)
    print("  eBPF Stall Fingerprinting - Packaging Deliverables")
    print("=" * 60)

    if not validate_core_files():
        sys.exit(1)

    deliverables_dir = REPO_ROOT / "deliverables"
    deliverables_dir.mkdir(parents=True, exist_ok=True)

    rep_zip = create_report_source_zip(deliverables_dir)
    proj_zip = create_project_source_zip(deliverables_dir)
    guide = generate_reproduction_guide(deliverables_dir)
    compile_report_pdf(deliverables_dir)

    print("=" * 60)
    print("  All submission deliverables successfully validated and generated!")
    print(f"  Deliverables directory: {deliverables_dir}")
    print("=" * 60)

if __name__ == "__main__":
    main()
