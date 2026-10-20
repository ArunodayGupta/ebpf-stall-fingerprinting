# Environment Setup & Preflight Guide

This guide details the system requirements, installation procedures, and execution steps for the **eBPF-Based Application Stall Fingerprinting** research project on Kali Linux inside Oracle VirtualBox.

---

## 1. System Requirements & Architecture

| Component | Target Requirement | Recommended Configuration |
|---|---|---|
| **Operating System** | Linux (Debian-derived / Kali Rolling) | Kali Linux 2024.x / 2026.x x86_64 |
| **Virtualization** | Oracle VirtualBox 7.x | 2–4 vCPUs, 2048–4096 MB RAM |
| **Kernel** | Linux Kernel >= 5.10 with BPF enabled | Linux 6.x (default in modern Kali) |
| **Kernel Headers** | Matching running kernel (`uname -r`) | `linux-headers-$(uname -r)` |
| **BPF Toolchain** | BCC (BPF Compiler Collection) | `bpfcc-tools`, `python3-bpfcc` |
| **Python** | Python 3.9+ | Python 3.11 / 3.12 |
| **Data Science Libraries** | NumPy, Pandas, Scikit-learn, SciPy, Matplotlib | Installed via pip or apt |

---

## 2. VirtualBox Kali VM Setup

### A. Virtual Machine Hardware Settings
1. Open **Oracle VM VirtualBox Manager**.
2. Select the VM (e.g. `kali-linux-2026.2-virtualbox-amd64`).
3. Under **Settings -> System -> Processor**, allocate at least **2 vCPUs** (4 recommended for scheduler contention experiments).
4. Under **Settings -> System -> Motherboard**, allocate at least **2048 MB RAM** (4096 MB recommended).
5. Under **Settings -> Network -> Adapter 1**:
   - Attached to: **NAT**
   - Click **Advanced -> Port Forwarding**:
     - Name: `SSH`, Protocol: `TCP`, Host IP: `127.0.0.1`, Host Port: `2222`, Guest Port: `22`.

### B. Shared Folder Setup (Host to Guest)
To synchronize the project repository between the Windows host (`D:\OS_Project\ebpf-stall-fingerprinting`) and the Kali VM:
1. Under **Settings -> Shared Folders**, add a new shared folder:
   - Folder Path: `D:\OS_Project\ebpf-stall-fingerprinting`
   - Folder Name: `ebpf_project`
   - Auto-mount: Checked
   - Access: Full read/write
2. Inside the Kali VM:
   ```bash
   sudo mkdir -p /mnt/ebpf_project
   sudo mount -t vboxsf ebpf_project /mnt/ebpf_project
   # Or add user to vboxsf group:
   sudo usermod -aG vboxsf $USER
   ```

---

## 3. Kali Linux Dependency Installation

Log into the Kali VM (default credentials: `kali` / `kali`), open a terminal, and run:

```bash
# 1. Update package lists
sudo apt update

# 2. Install kernel headers matching the active kernel
sudo apt install -y linux-headers-$(uname -r)

# 3. Install BCC, Clang, LLVM, and Python BCC bindings
sudo apt install -y bpfcc-tools python3-bpfcc libbpf-dev clang llvm

# 4. Install Python scientific stack & tools
sudo apt install -y python3-pip python3-numpy python3-pandas python3-sklearn \
                    python3-scipy python3-matplotlib python3-seaborn \
                    python3-yaml python3-psutil python3-pytest

# 5. (Optional) Install LaTeX toolchain for report compilation
sudo apt install -y texlive-latex-base texlive-latex-recommended texlive-fonts-recommended
```

---

## 4. Running the Environment Preflight Checker

Verify that all kernel headers, BCC bindings, tracepoints, and permissions are correctly configured:

```bash
cd /mnt/ebpf_project  # or cloned repository directory
python3 scripts/check_environment.py
```

### Expected Output in Kali:
```
======================================================================
  eBPF Stall Fingerprinting - Environment Preflight Diagnostic
======================================================================
OS System:       Linux 6.x.x-amd64
Distro:          Kali GNU/Linux Rolling
Architecture:    x86_64
Kernel Release:  6.x.x-amd64
Logical CPUs:    2
RAM Total:       2.00 GB
Python:          3.11.x / 3.12.x
BCC Status:      ready
Privileges:      Running with root privileges (or non-root note)
----------------------------------------------------------------------
Kernel Tracing Capabilities:
  Headers:       present (/lib/modules/6.x.x-amd64/build)
  Tracepoints:   17/17 supported
    syscalls:sys_enter_read       : OK
    syscalls:sys_exit_read        : OK
    syscalls:sys_enter_write      : OK
    syscalls:sys_exit_write       : OK
    block:block_rq_issue          : OK
    block:block_rq_complete       : OK
    sched:sched_wakeup            : OK
    sched:sched_switch            : OK
----------------------------------------------------------------------
Overall Status:  READY
Can Run Tests:   True
Can Run eBPF:    True
```

The manifest will be saved to `results/environment_manifest.json`.

---

## 5. Kernel Tracing Privileges & Capabilities

Kernel tracing requires elevated privileges:
- Running eBPF collector scripts requires `sudo` privileges because tracepoint attachment (`BPF_PROG_TYPE_TRACEPOINT`) accesses kernel tracefs and creates BPF maps.
- **Security Policy**: Workload generator processes are spawned as ordinary unprivileged user processes, while only the BPF supervisor/collector requires elevated privileges.
- Do **not** disable system security settings (e.g. SELinux/AppArmor) or modify production scheduler policies.

---

## 6. Verifying Tracepoints Manually

To verify tracepoints directly in sysfs:
```bash
# Check if tracefs is mounted
mount | grep tracefs

# Verify syscall tracepoint format
cat /sys/kernel/tracing/events/syscalls/sys_enter_read/format

# Verify block request tracepoint format
cat /sys/kernel/tracing/events/block/block_rq_issue/format

# Verify scheduler switch tracepoint format
cat /sys/kernel/tracing/events/sched/sched_switch/format
```

If tracefs is not mounted, mount it with:
```bash
sudo mount -t tracefs nodev /sys/kernel/tracing
```
