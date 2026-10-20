#!/usr/bin/env bash
# Package submission script for Linux / Kali VM
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running Submission Packaging Suite ==="
cd "$REPO_ROOT"
python3 scripts/package_submission.py
echo "=== Packaging Complete ==="
