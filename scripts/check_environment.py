#!/usr/bin/env python3
"""
Environment Preflight Checker for eBPF Application Stall Fingerprinting.

This script inspects and reports:
1. OS, distribution, and kernel information
2. Hardware resources (CPU cores, RAM, storage)
3. BCC (BPF Compiler Collection) availability and Python bindings
4. Linux kernel headers and kernel build directory
5. Kernel configuration symbols (CONFIG_BPF, CONFIG_BPF_SYSCALL, etc.)
6. Kernel tracepoints for syscalls, block I/O, and scheduler events
7. BPF loading privileges and effective capabilities
8. Software and Python library dependencies (numpy, pandas, sklearn, matplotlib, etc.)
9. Host virtualization context (Windows host, VirtualBox VM, WSL)

Outputs:
- Console diagnostic report
- results/environment_manifest.json
"""

import sys
import os
import platform
import subprocess
import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional

def get_distro_info() -> Dict[str, str]:
    distro_info = {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "distro_id": "unknown",
        "distro_version": "unknown",
        "distro_pretty_name": "unknown",
    }
    os_release_path = Path("/etc/os-release")
    if os_release_path.exists():
        try:
            with open(os_release_path, "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        v = v.strip('"\'')
                        if k == "ID":
                            distro_info["distro_id"] = v
                        elif k == "VERSION_ID":
                            distro_info["distro_version"] = v
                        elif k == "PRETTY_NAME":
                            distro_info["distro_pretty_name"] = v
        except Exception as e:
            distro_info["os_release_error"] = str(e)
    elif platform.system() == "Windows":
        distro_info["distro_id"] = "windows"
        distro_info["distro_pretty_name"] = f"Windows {platform.version()}"
    return distro_info

def get_hardware_info() -> Dict[str, Any]:
    hw = {
        "cpu_count_logical": os.cpu_count() or 1,
        "cpu_count_physical": os.cpu_count() or 1,
        "ram_total_bytes": 0,
        "ram_total_gb": 0.0,
        "storage_partitions": [],
    }
    try:
        import psutil
        hw["cpu_count_logical"] = psutil.cpu_count(logical=True)
        hw["cpu_count_physical"] = psutil.cpu_count(logical=False) or hw["cpu_count_logical"]
        vm = psutil.virtual_memory()
        hw["ram_total_bytes"] = vm.total
        hw["ram_total_gb"] = round(vm.total / (1024 ** 3), 2)
        hw["ram_available_gb"] = round(vm.available / (1024 ** 3), 2)
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                hw["storage_partitions"].append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                })
            except Exception:
                pass
    except ImportError:
        pass
    return hw

def check_kernel_headers(kernel_release: str) -> Dict[str, Any]:
    res = {
        "available": False,
        "path": None,
        "status": "absent",
        "detail": "",
    }
    if platform.system() != "Linux":
        res["detail"] = "Host is not Linux; kernel headers only exist on Linux systems."
        return res

    candidate_paths = [
        Path(f"/lib/modules/{kernel_release}/build"),
        Path(f"/lib/modules/{kernel_release}/source"),
        Path(f"/usr/src/linux-headers-{kernel_release}"),
    ]
    for p in candidate_paths:
        if p.exists() and (p / "include").exists():
            res["available"] = True
            res["path"] = str(p)
            res["status"] = "present"
            res["detail"] = f"Found kernel headers at {p}"
            return res

    res["detail"] = (
        f"Kernel headers for {kernel_release} not found in /lib/modules or /usr/src. "
        f"Install via: sudo apt install -y linux-headers-{kernel_release}"
    )
    return res

def check_kernel_config() -> Dict[str, Any]:
    res = {
        "status": "unknown",
        "config_file": None,
        "symbols": {},
        "missing_critical": [],
    }
    if platform.system() != "Linux":
        res["status"] = "not_applicable"
        return res

    kernel_release = platform.release()
    candidate_configs = [
        Path(f"/boot/config-{kernel_release}"),
        Path("/proc/config.gz"),
    ]

    config_lines = []
    for cfg in candidate_configs:
        if cfg.exists():
            res["config_file"] = str(cfg)
            try:
                if str(cfg).endswith(".gz"):
                    import gzip
                    with gzip.open(cfg, "rt") as f:
                        config_lines = f.readlines()
                else:
                    with open(cfg, "r", encoding="utf-8", errors="ignore") as f:
                        config_lines = f.readlines()
                res["status"] = "inspected"
                break
            except Exception as e:
                res["error"] = str(e)

    critical_symbols = [
        "CONFIG_BPF",
        "CONFIG_BPF_SYSCALL",
        "CONFIG_BPF_EVENTS",
        "CONFIG_KPROBES",
        "CONFIG_TRACEPOINTS",
        "CONFIG_PERF_EVENTS",
    ]

    symbol_map = {}
    for line in config_lines:
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            symbol_map[k] = v

    for sym in critical_symbols:
        val = symbol_map.get(sym, "not_set")
        res["symbols"][sym] = val
        if val not in ("y", "m"):
            res["missing_critical"].append(sym)

    return res

def check_tracepoints() -> Dict[str, Any]:
    res = {
        "tracefs_mounted": False,
        "tracefs_path": None,
        "tracepoints": {},
    }
    if platform.system() != "Linux":
        return res

    tracing_paths = [
        Path("/sys/kernel/tracing"),
        Path("/sys/kernel/debug/tracing"),
    ]
    tracefs = None
    for p in tracing_paths:
        if p.exists() and (p / "events").exists():
            tracefs = p
            break

    if not tracefs:
        res["error"] = "Neither /sys/kernel/tracing nor /sys/kernel/debug/tracing is mounted"
        return res

    res["tracefs_mounted"] = True
    res["tracefs_path"] = str(tracefs)

    target_tracepoints = [
        ("syscalls", "sys_enter_read"),
        ("syscalls", "sys_exit_read"),
        ("syscalls", "sys_enter_pread64"),
        ("syscalls", "sys_exit_pread64"),
        ("syscalls", "sys_enter_write"),
        ("syscalls", "sys_exit_write"),
        ("syscalls", "sys_enter_pwrite64"),
        ("syscalls", "sys_exit_pwrite64"),
        ("syscalls", "sys_enter_fsync"),
        ("syscalls", "sys_exit_fsync"),
        ("syscalls", "sys_enter_fdatasync"),
        ("syscalls", "sys_exit_fdatasync"),
        ("block", "block_rq_issue"),
        ("block", "block_rq_complete"),
        ("sched", "sched_wakeup"),
        ("sched", "sched_wakeup_new"),
        ("sched", "sched_switch"),
    ]

    for category, name in target_tracepoints:
        key = f"{category}:{name}"
        tp_dir = tracefs / "events" / category / name
        tp_format = tp_dir / "format"
        if tp_dir.exists() and tp_format.exists():
            fields = []
            try:
                with open(tp_format, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("field:"):
                            fields.append(line)
            except Exception:
                pass
            res["tracepoints"][key] = {
                "available": True,
                "path": str(tp_dir),
                "field_count": len(fields),
                "sample_fields": fields[:4],
            }
        else:
            res["tracepoints"][key] = {
                "available": False,
                "path": str(tp_dir),
            }

    return res

def check_bcc() -> Dict[str, Any]:
    res = {
        "available": False,
        "import_error": None,
        "bpf_class_available": False,
        "status": "absent",
    }
    try:
        import bcc
        res["available"] = True
        res["bpf_class_available"] = hasattr(bcc, "BPF")
        res["version"] = getattr(bcc, "__version__", "unknown")
        res["status"] = "ready"
    except ImportError as e:
        res["import_error"] = str(e)
        res["status"] = "dependency_missing"
    except Exception as e:
        res["import_error"] = str(e)
        res["status"] = "error"
    return res

def check_privileges() -> Dict[str, Any]:
    res = {
        "is_root": False,
        "euid": getattr(os, "geteuid", lambda: -1)(),
        "bpf_capable": False,
        "detail": "",
    }
    if platform.system() == "Linux":
        if res["euid"] == 0:
            res["is_root"] = True
            res["bpf_capable"] = True
            res["detail"] = "Running with root privileges (EUID 0); eBPF program loading supported."
        else:
            res["is_root"] = False
            res["bpf_capable"] = False
            res["detail"] = "Non-root user. Loading eBPF programs generally requires root (sudo) or CAP_BPF / CAP_SYS_ADMIN capabilities."
    else:
        res["detail"] = "Host is Windows; Linux kernel privileges not applicable."
    return res

def check_dependencies() -> Dict[str, Any]:
    res = {
        "python_version": sys.version,
        "python_executable": sys.executable,
        "packages": {},
        "compilers": {},
        "latex": {},
    }

    target_packages = [
        "numpy",
        "pandas",
        "sklearn",
        "scipy",
        "matplotlib",
        "seaborn",
        "yaml",
        "psutil",
        "pytest",
    ]
    for pkg in target_packages:
        try:
            mod = __import__(pkg)
            ver = getattr(mod, "__version__", "installed")
            res["packages"][pkg] = {"installed": True, "version": ver}
        except ImportError:
            res["packages"][pkg] = {"installed": False, "version": None}

    compilers = ["gcc", "clang", "llvm-strip"]
    for comp in compilers:
        found_path = shutil.which(comp)
        res["compilers"][comp] = {
            "available": found_path is not None,
            "path": found_path,
        }

    latex_tools = ["pdflatex", "latexmk", "xelatex"]
    for tool in latex_tools:
        found_path = shutil.which(tool)
        res["latex"][tool] = {
            "available": found_path is not None,
            "path": found_path,
        }

    return res

def inspect_virtualization() -> Dict[str, Any]:
    res = {
        "is_vm": False,
        "vm_type": "none",
        "vbox_manage_on_host": False,
        "known_vms": [],
    }
    # Check if running inside VirtualBox VM (Linux guest)
    dmi_sys_vendor = Path("/sys/class/dmi/id/sys_vendor")
    dmi_product = Path("/sys/class/dmi/id/product_name")
    if dmi_sys_vendor.exists():
        try:
            vendor = dmi_sys_vendor.read_text().strip()
            product = dmi_product.read_text().strip() if dmi_product.exists() else ""
            if "VirtualBox" in vendor or "VirtualBox" in product:
                res["is_vm"] = True
                res["vm_type"] = "Oracle VirtualBox"
        except Exception:
            pass

    # Check if running on Windows host with VirtualBox installed
    if platform.system() == "Windows":
        vbox_candidates = [
            Path("C:/Program Files/Oracle/VirtualBox/VBoxManage.exe"),
            Path("C:/Program Files (x86)/Oracle/VirtualBox/VBoxManage.exe"),
        ]
        for v in vbox_candidates:
            if v.exists():
                res["vbox_manage_on_host"] = True
                res["vbox_path"] = str(v)
                try:
                    out = subprocess.check_output([str(v), "list", "vms"], text=True)
                    for line in out.strip().splitlines():
                        if line:
                            res["known_vms"].append(line.strip())
                except Exception:
                    pass
                break
    return res

def generate_manifest(output_path: Path) -> Dict[str, Any]:
    manifest = {
        "schema_version": "1.0",
        "check_timestamp": platform.uname().node,
        "distro": get_distro_info(),
        "hardware": get_hardware_info(),
        "privileges": check_privileges(),
        "kernel_release": platform.release(),
        "kernel_headers": check_kernel_headers(platform.release()),
        "kernel_config": check_kernel_config(),
        "tracepoints": check_tracepoints(),
        "bcc": check_bcc(),
        "dependencies": check_dependencies(),
        "virtualization": inspect_virtualization(),
        "summary": {},
    }

    # Synthesize readiness summary
    is_linux = manifest["distro"]["os_name"] == "Linux"
    has_bcc = manifest["bcc"]["available"]
    has_root = manifest["privileges"]["is_root"]
    missing_pkgs = [k for k, v in manifest["dependencies"]["packages"].items() if not v["installed"]]

    status_code = "READY"
    action_items = []

    if not is_linux:
        status_code = "HOST_NOT_LINUX"
        action_items.append(
            "Current execution environment is Windows. eBPF kernel tracing requires a Linux kernel. "
            "Execute the suite inside the target Kali Linux VirtualBox VM."
        )
    else:
        if not has_bcc:
            status_code = "BCC_MISSING"
            action_items.append("BCC Python bindings not installed. Run: sudo apt install -y bpfcc-tools python3-bpfcc")
        if not manifest["kernel_headers"]["available"]:
            action_items.append(f"Kernel headers missing. Run: sudo apt install -y linux-headers-{platform.release()}")
        if not has_root:
            action_items.append("Root privileges required for eBPF attachment. Run experiment commands with 'sudo'.")
        if missing_pkgs:
            action_items.append(f"Missing Python packages: {', '.join(missing_pkgs)}. Run: pip install -r requirements.txt")

    manifest["summary"] = {
        "status_code": status_code,
        "can_run_unit_tests": len(missing_pkgs) == 0,
        "can_run_real_ebpf": is_linux and has_bcc and has_root,
        "action_items": action_items,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest

def print_report(m: Dict[str, Any]):
    print("=" * 70)
    print("  eBPF Stall Fingerprinting - Environment Preflight Diagnostic")
    print("=" * 70)
    print(f"OS System:       {m['distro']['os_name']} {m['distro']['os_release']}")
    print(f"Distro:          {m['distro'].get('distro_pretty_name', 'N/A')}")
    print(f"Architecture:    {m['distro']['machine']}")
    print(f"Kernel Release:  {m['kernel_release']}")
    print(f"Logical CPUs:    {m['hardware']['cpu_count_logical']}")
    print(f"RAM Total:       {m['hardware']['ram_total_gb']} GB (Available: {m['hardware'].get('ram_available_gb', 'N/A')} GB)")
    print(f"Python:          {m['dependencies']['python_version'].split()[0]}")
    print(f"BCC Status:      {m['bcc']['status']}")
    print(f"Privileges:      {m['privileges']['detail']}")

    virt = m["virtualization"]
    if virt.get("is_vm"):
        print(f"Virtualization:  Running inside VM ({virt.get('vm_type')})")
    elif virt.get("vbox_manage_on_host"):
        print(f"Virtualization:  Windows host with VirtualBox installed.")
        for vm in virt.get("known_vms", []):
            print(f"                 Detected VM: {vm}")

    print("-" * 70)
    print("Python Packages:")
    for pkg, info in m["dependencies"]["packages"].items():
        state = f"OK (v{info['version']})" if info["installed"] else "MISSING"
        print(f"  {pkg:15s}: {state}")

    print("-" * 70)
    print("Kernel Tracing Capabilities:")
    if m["distro"]["os_name"] == "Linux":
        print(f"  Headers:       {m['kernel_headers']['status']} ({m['kernel_headers'].get('path')})")
        tp_dict = m["tracepoints"].get("tracepoints", {})
        available_tps = sum(1 for v in tp_dict.values() if v.get("available"))
        total_tps = len(tp_dict)
        print(f"  Tracepoints:   {available_tps}/{total_tps} supported")
        for tp_name, tp_info in tp_dict.items():
            st = "OK" if tp_info.get("available") else "UNAVAILABLE"
            print(f"    {tp_name:30s}: {st}")
    else:
        print("  Kernel headers / tracepoints check skipped (host is Windows).")

    print("-" * 70)
    summary = m["summary"]
    print(f"Overall Status:  {summary['status_code']}")
    print(f"Can Run Tests:   {summary['can_run_unit_tests']}")
    print(f"Can Run eBPF:    {summary['can_run_real_ebpf']}")

    if summary["action_items"]:
        print("\nAction Items:")
        for idx, item in enumerate(summary["action_items"], 1):
            print(f"  [{idx}] {item}")
    print("=" * 70)

def main():
    repo_root = Path(__file__).resolve().parent.parent
    manifest_path = repo_root / "results" / "environment_manifest.json"
    manifest = generate_manifest(manifest_path)
    print_report(manifest)
    print(f"\nManifest written to: {manifest_path}")

if __name__ == "__main__":
    main()
