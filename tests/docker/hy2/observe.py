#!/usr/bin/env python3
"""One read-only container snapshot; no dependency on iproute2 or procps."""

import argparse
import datetime
import json
from pathlib import Path


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def paired_counters(path):
    lines = (read(path) or "").splitlines()
    result = {}
    for header, values in zip(lines[::2], lines[1::2]):
        keys, data = header.split(), values.split()
        if keys and data and keys[0] == data[0]:
            result[keys[0].rstrip(":")] = {
                key: int(value) for key, value in zip(keys[1:], data[1:])
            }
    return result


def udp_sockets(path):
    sockets = []
    for line in (read(path) or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) < 13:
            continue
        tx, rx = fields[4].split(":")
        sockets.append(
            {
                "local": fields[1],
                "remote": fields[2],
                "state": fields[3],
                "tx_queue_bytes": int(tx, 16),
                "rx_queue_bytes": int(rx, 16),
                "inode": int(fields[9]),
                "drops": int(fields[-1]),
            }
        )
    return sockets


def process(state_dir, name):
    raw_pid = read(state_dir / (name + ".pid"))
    if raw_pid is None or not raw_pid.isdecimal():
        return {"pid": raw_pid, "running": False}
    proc = Path("/proc") / raw_pid
    status = read(proc / "status")
    info = {"pid": int(raw_pid), "running": status is not None}
    if status is not None:
        info["status"] = dict(
            line.split(":", 1) for line in status.splitlines() if ":" in line
        )
        info["status"] = {key: value.strip() for key, value in info["status"].items()}
        info["io"] = read(proc / "io")
        info["wchan"] = read(proc / "wchan")
        try:
            info["open_fds"] = sum(1 for _ in (proc / "fd").iterdir())
        except OSError:
            info["open_fds"] = None
    return info


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, default=Path("/fixture"))
    args = parser.parse_args()
    cgroup_names = (
        "memory.current", "memory.peak", "memory.events", "memory.max",
        "cpu.stat", "cpu.max", "pids.current", "pids.max",
    )
    result = {
        "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snmp": paired_counters("/proc/net/snmp"),
        "netstat": paired_counters("/proc/net/netstat"),
        "sockstat": read("/proc/net/sockstat"),
        "sockstat6": read("/proc/net/sockstat6"),
        "udp": udp_sockets("/proc/net/udp"),
        "udp6": udp_sockets("/proc/net/udp6"),
        "agent": process(args.state_dir, "agent"),
        "fixture": process(args.state_dir, "fixture"),
        "cgroup": {name: read(Path("/sys/fs/cgroup") / name) for name in cgroup_names},
    }
    for name in ("ready", "stats"):
        try:
            result[name] = json.loads(read(args.state_dir / (name + ".json")) or "null")
        except ValueError:
            result[name] = None
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
