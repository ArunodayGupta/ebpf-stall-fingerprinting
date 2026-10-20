"""
eBPF C Source Code and Definitions for Stall Fingerprinting.

Contains embedded C code loaded by BCC into the Linux kernel to trace:
1. Syscalls (read, write, pread64, pwrite64, fsync, fdatasync)
2. Block layer request issue and completion (block_rq_issue, block_rq_complete)
3. Scheduler wakeups and switches (sched_wakeup, sched_wakeup_new, sched_switch)
"""

import ctypes

BPF_C_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EV_SYSCALL_COMPLETE 1
#define EV_BLOCK_RQ_ISSUE    2
#define EV_BLOCK_RQ_COMPLETE 3
#define EV_SCHED_WAKEUP      4
#define EV_SCHED_SWITCH      5

struct kernel_event_t {
    u32 event_type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char comm[16];

    // Syscall fields
    u32 syscall_id;
    u64 duration_ns;
    s64 ret;

    // Block fields
    u32 dev;
    u64 sector;
    u32 nr_sector;
    u32 bytes_count;
    char rwbs[8];
    s32 error;

    // Sched fields
    u32 prev_pid;
    u32 next_pid;
    s64 prev_state;
    u8 is_on_cpu;
    u64 runnable_delay_ns;
};

// Target PIDs filter map: key = PID (tgid), val = 1
BPF_HASH(target_pids, u32, u8, 1024);

// Syscall start tracking map: key = tgid, val = start_timestamp_ns
BPF_HASH(syscall_starts, u64, u64, 4096);

// Scheduler runnable start tracking: key = pid, val = wakeup_timestamp_ns
BPF_HASH(runnable_starts, u32, u64, 4096);

// Perf output ring buffer
BPF_PERF_OUTPUT(events);

static inline u8 is_target_pid(u32 pid) {
    u8 *val = target_pids.lookup(&pid);
    return val != NULL;
}

// -------------------------------------------------------------
// Syscall Tracing Helpers
// -------------------------------------------------------------
static inline void record_syscall_enter(void *ctx, u32 syscall_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;

    if (!is_target_pid(tgid)) {
        return;
    }

    u64 now = bpf_ktime_get_ns();
    u64 key = ((u64)tgid << 32) | (u64)syscall_id;
    syscall_starts.update(&key, &now);
}

static inline void record_syscall_exit(void *ctx, u32 syscall_id, s64 ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (!is_target_pid(tgid)) {
        return;
    }

    u64 key = ((u64)tgid << 32) | (u64)syscall_id;
    u64 *start_ns = syscall_starts.lookup(&key);
    if (!start_ns) {
        return;
    }

    u64 now = bpf_ktime_get_ns();
    u64 duration = now - *start_ns;
    syscall_starts.delete(&key);

    struct kernel_event_t ev = {};
    ev.event_type = EV_SYSCALL_COMPLETE;
    ev.timestamp_ns = now;
    ev.pid = tgid;
    ev.tid = tid;
    ev.syscall_id = syscall_id;
    ev.duration_ns = duration;
    ev.ret = ret;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    events.perf_submit(ctx, &ev, sizeof(ev));
}

// Tracepoints for syscalls: sys_enter_* and sys_exit_*
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    record_syscall_enter(args, 0);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    record_syscall_exit(args, 0, args->ret);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    record_syscall_enter(args, 1);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    record_syscall_exit(args, 1, args->ret);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pread64) {
    record_syscall_enter(args, 17);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_pread64) {
    record_syscall_exit(args, 17, args->ret);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
    record_syscall_enter(args, 18);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_pwrite64) {
    record_syscall_exit(args, 18, args->ret);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fsync) {
    record_syscall_enter(args, 74);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_fsync) {
    record_syscall_exit(args, 74, args->ret);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fdatasync) {
    record_syscall_enter(args, 75);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_fdatasync) {
    record_syscall_exit(args, 75, args->ret);
    return 0;
}

// -------------------------------------------------------------
// Block Layer Tracing
// -------------------------------------------------------------
TRACEPOINT_PROBE(block, block_rq_issue) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;

    struct kernel_event_t ev = {};
    ev.event_type = EV_BLOCK_RQ_ISSUE;
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = tgid;
    ev.tid = (u32)pid_tgid;
    ev.dev = args->dev;
    ev.sector = args->sector;
    ev.nr_sector = args->nr_sector;
    ev.bytes_count = args->bytes;
    bpf_probe_read_kernel_str(&ev.rwbs, sizeof(ev.rwbs), args->rwbs);
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;

    struct kernel_event_t ev = {};
    ev.event_type = EV_BLOCK_RQ_COMPLETE;
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = tgid;
    ev.tid = (u32)pid_tgid;
    ev.dev = args->dev;
    ev.sector = args->sector;
    ev.nr_sector = args->nr_sector;
    ev.error = args->error;
    bpf_probe_read_kernel_str(&ev.rwbs, sizeof(ev.rwbs), args->rwbs);
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

// -------------------------------------------------------------
// Scheduler Tracing
// -------------------------------------------------------------
static inline void handle_wakeup(void *ctx, u32 pid) {
    if (!is_target_pid(pid)) {
        return;
    }

    u64 now = bpf_ktime_get_ns();
    runnable_starts.update(&pid, &now);

    struct kernel_event_t ev = {};
    ev.event_type = EV_SCHED_WAKEUP;
    ev.timestamp_ns = now;
    ev.pid = pid;
    events.perf_submit(ctx, &ev, sizeof(ev));
}

TRACEPOINT_PROBE(sched, sched_wakeup) {
    handle_wakeup(args, args->pid);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup_new) {
    handle_wakeup(args, args->pid);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    u64 now = bpf_ktime_get_ns();

    // 1. Next task scheduled onto CPU
    if (is_target_pid(next_pid)) {
        u64 *start_ns = runnable_starts.lookup(&next_pid);
        u64 runnable_delay = 0;
        if (start_ns) {
            runnable_delay = now - *start_ns;
            runnable_starts.delete(&next_pid);
        }

        struct kernel_event_t ev = {};
        ev.event_type = EV_SCHED_SWITCH;
        ev.timestamp_ns = now;
        ev.pid = next_pid;
        ev.prev_pid = prev_pid;
        ev.next_pid = next_pid;
        ev.prev_state = args->prev_state;
        ev.is_on_cpu = 1;
        ev.runnable_delay_ns = runnable_delay;
        events.perf_submit(args, &ev, sizeof(ev));
    }

    // 2. Previous task scheduled off CPU
    if (is_target_pid(prev_pid)) {
        // If state is 0 (TASK_RUNNING), it was preempted and remains runnable
        if (args->prev_state == 0) {
            runnable_starts.update(&prev_pid, &now);
        }

        struct kernel_event_t ev = {};
        ev.event_type = EV_SCHED_SWITCH;
        ev.timestamp_ns = now;
        ev.pid = prev_pid;
        ev.prev_pid = prev_pid;
        ev.next_pid = next_pid;
        ev.prev_state = args->prev_state;
        ev.is_on_cpu = 0;
        ev.runnable_delay_ns = 0;
        events.perf_submit(args, &ev, sizeof(ev));
    }

    return 0;
}
"""

class KernelEventCStruct(ctypes.Structure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("syscall_id", ctypes.c_uint32),
        ("duration_ns", ctypes.c_uint64),
        ("ret", ctypes.c_int64),
        ("dev", ctypes.c_uint32),
        ("sector", ctypes.c_uint64),
        ("nr_sector", ctypes.c_uint32),
        ("bytes_count", ctypes.c_uint32),
        ("rwbs", ctypes.c_char * 8),
        ("error", ctypes.c_int32),
        ("prev_pid", ctypes.c_uint32),
        ("next_pid", ctypes.c_uint32),
        ("prev_state", ctypes.c_int64),
        ("is_on_cpu", ctypes.c_uint8),
        ("runnable_delay_ns", ctypes.c_uint64),
    ]

SYSCALL_ID_TO_NAME = {
    0: "read",
    1: "write",
    17: "pread64",
    18: "pwrite64",
    74: "fsync",
    75: "fdatasync",
}
