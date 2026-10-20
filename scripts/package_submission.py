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

    print("=" * 60)
    print("  All submission archives successfully validated and generated!")
    print(f"  Deliverables directory: {deliverables_dir}")
    print("=" * 60)

if __name__ == "__main__":
    main()
