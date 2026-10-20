"""
Unit tests for event schema serialization, parsing, and validation.
"""

import pytest
import json
from pathlib import Path
from stall_fingerprint.event_schema import (
    EventType,
    BaseEvent,
    SyscallEvent,
    BlockEvent,
    SchedEvent,
    DiagnosticEvent,
    DroppedEventStats,
    parse_event,
    EventWriter,
    EventReader,
    SCHEMA_VERSION,
)

def test_syscall_event_serialization():
    ev = SyscallEvent(
        event_type=EventType.SYSCALL_COMPLETE.value,
        timestamp_ns=1000000000,
        pid=1234,
        tid=1234,
        comm="test_proc",
        syscall_name="fsync",
        syscall_id=74,
        duration_ns=5000000,
        ret=0,
    )
    json_str = ev.to_json()
    parsed = parse_event(json_str)

    assert isinstance(parsed, SyscallEvent)
    assert parsed.event_type == EventType.SYSCALL_COMPLETE.value
    assert parsed.pid == 1234
    assert parsed.syscall_name == "fsync"
    assert parsed.duration_ns == 5000000
    assert parsed.schema_version == SCHEMA_VERSION

def test_block_event_serialization():
    ev = BlockEvent(
        event_type=EventType.BLOCK_RQ_ISSUE.value,
        timestamp_ns=2000000000,
        dev=2049,
        sector=1024,
        nr_sector=8,
        bytes_count=4096,
        rwbs="WS",
        pid=1234,
    )
    json_str = ev.to_json()
    parsed = parse_event(json_str)

    assert isinstance(parsed, BlockEvent)
    assert parsed.bytes_count == 4096
    assert parsed.rwbs == "WS"

def test_sched_event_serialization():
    ev = SchedEvent(
        event_type=EventType.SCHED_SWITCH.value,
        timestamp_ns=3000000000,
        prev_pid=100,
        next_pid=1234,
        prev_state=0,
        target_pid=1234,
        is_on_cpu=True,
        runnable_delay_ns=1200000,
    )
    json_str = ev.to_json()
    parsed = parse_event(json_str)

    assert isinstance(parsed, SchedEvent)
    assert parsed.is_on_cpu is True
    assert parsed.runnable_delay_ns == 1200000

def test_event_writer_and_reader(tmp_path: Path):
    test_file = tmp_path / "events.jsonl"
    events = [
        SyscallEvent(event_type=EventType.SYSCALL_COMPLETE.value, timestamp_ns=100, pid=1, syscall_name="read"),
        BlockEvent(event_type=EventType.BLOCK_RQ_COMPLETE.value, timestamp_ns=200, pid=1, bytes_count=1024),
        DroppedEventStats(event_type=EventType.DROPPED_EVENT_STATS.value, timestamp_ns=300, total_events_lost=5),
    ]

    with EventWriter(test_file) as writer:
        for ev in events:
            writer.write_event(ev)

    reader = EventReader(test_file)
    loaded = reader.read_all()

    assert len(loaded) == 3
    assert loaded[0].event_type == EventType.SYSCALL_COMPLETE.value
    assert loaded[1].event_type == EventType.BLOCK_RQ_COMPLETE.value
    assert loaded[2].event_type == EventType.DROPPED_EVENT_STATS.value
    assert getattr(loaded[2], "total_events_lost") == 5

def test_corrupt_lines_tolerance(tmp_path: Path):
    test_file = tmp_path / "corrupt_events.jsonl"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write('{"event_type": "SYSCALL_COMPLETE", "timestamp_ns": 100, "pid": 1}\n')
        f.write('this is not valid json\n')
        f.write('{"event_type": "BLOCK_RQ_COMPLETE", "timestamp_ns": 200, "pid": 1}\n')

    reader = EventReader(test_file)
    loaded = reader.read_all()
    assert len(loaded) == 3
    # Middle event is converted to a DiagnosticEvent
    assert loaded[1].event_type == EventType.COLLECTOR_DIAGNOSTIC.value
    assert "Corrupt event line 2" in getattr(loaded[1], "message")
