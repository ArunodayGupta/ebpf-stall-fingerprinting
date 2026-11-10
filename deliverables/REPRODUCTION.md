# Reproduction Guide

Run from the repository root on Linux. The live collector needs BCC, matching kernel headers, and root or equivalent BPF capabilities. Do not run the real experiment with `--allow-synthetic-dev-only`.

## Install

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) bpfcc-tools python3-bpfcc python3-venv python3-pip texlive-latex-base texlive-latex-recommended
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run and collect

```bash
.venv/bin/python scripts/check_environment.py
.venv/bin/python -m pytest tests -v
sudo .venv/bin/python scripts/smoke_test.py
sudo .venv/bin/python scripts/run_experiments.py --profile full
```

The full profile runs five repetitions at concurrency 1, 2, and 4. Reads use 8 MiB and 32 MiB files with warm and best-effort cold-cache conditions. Synchronous writes use both sizes. `posix_fadvise(POSIX_FADV_DONTNEED)` is advisory; the cold-cache label describes the intervention, not a guaranteed cache miss.

The runner creates `results/run_<timestamp>_full/` with raw events, workload labels and boundaries, extracted features and predictions, baseline metrics, a held-out file-size transfer evaluation, I/O throughput summaries, and the overhead budget result. The process CPU metric is measured per workload process. Stall-duration error uses the configured injected sleep duration only; it is not a storage-stall reference.

## Ablations, figures, and paper

After the run, set the run directory once and generate artifacts:

```bash
RUN_DIR=$(ls -dt results/run_*_full | head -n 1)
.venv/bin/python scripts/run_ablations.py "$RUN_DIR/features.csv"
.venv/bin/python scripts/generate_figures.py "$RUN_DIR"
.venv/bin/python scripts/generate_report_data.py "$RUN_DIR" report
(cd report && pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex)
```

Generated metrics and tables are measurements from that host. The report deliberately avoids claiming that H1 or H2 passed before the run. H2 diagnostics include abstention coverage and high-confidence error rate; inspect example predictions before describing abstention as having prevented a particular error.

To package source deliverables after review:

```bash
.venv/bin/python scripts/package_submission.py
```
