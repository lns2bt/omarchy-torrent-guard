"""Best-effort read-only usage of this app's processes and Linux cgroups.

No Docker socket, sudo, or periodically prompted privileged commands are needed.
CPU percentage is one logical CPU at 100%; container memory includes page cache.
"""
import os
from pathlib import Path
import re
import time


CGROUP = re.compile(r"^/system\.slice/docker-[0-9a-f]{64}\.scope$")


def _process_cgroup(pid):
    try:
        entry = next((line[3:] for line in (Path("/proc") / str(pid) / "cgroup").read_text().splitlines()
                      if line.startswith("0::")), "")
        if CGROUP.fullmatch(entry):
            return Path("/sys/fs/cgroup") / entry.lstrip("/")
    except (OSError, ValueError):
        pass
    return None


def _memory_and_cpu(path):
    try:
        memory = int((path / "memory.current").read_text().strip())
        usec = next(int(line.split()[1]) for line in (path / "cpu.stat").read_text().splitlines()
                    if line.startswith("usage_usec "))
        return memory, usec
    except (OSError, ValueError, StopIteration):
        return None


def _pid_stats(pid):
    try:
        proc = Path("/proc") / str(pid)
        raw = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
        # The first item after the command is state (field 3).
        parent = int(raw[1])
        ticks = int(raw[11]) + int(raw[12])
        rss_pages = int(raw[21])
        return parent, ticks, rss_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, IndexError, ValueError):
        return None


def _processes():
    try:
        for path in Path("/proc").iterdir():
            if path.name.isdigit():
                try:
                    name = (path / "cmdline").read_bytes().split(b"\0", 1)[0].decode("utf-8", "replace")
                    yield int(path.name), name.rsplit("/", 1)[-1]
                except OSError:
                    continue
    except OSError:
        return


def _disk_usage(root):
    total = 0
    try:
        for folder, _dirs, files in os.walk(root, followlinks=False):
            for name in files:
                path = Path(folder) / name
                if not path.is_symlink():
                    total += path.lstat().st_size
    except OSError:
        return None
    return total


class Usage:
    def __init__(self, root):
        self.root = Path(root)
        self.previous = {}
        self.last = 0
        self.value = {}

    def _entry(self, label, identity, data, now):
        if data is None:
            self.previous.pop(label, None)
            return None
        memory, cpu = data
        old = self.previous.get(label)
        percent = 0.0
        if old and old[0] == identity and now > old[2]:
            percent = max(0.0, min(100 * (os.cpu_count() or 1),
                                   (cpu - old[1]) / 1_000_000 / (now - old[2]) * 100))
        self.previous[label] = (identity, cpu, now)
        return {"memory": memory, "cpu": round(percent, 1)}

    def sample(self):
        now = time.monotonic()
        if now - self.last < 5:
            return self.value
        matches = {"vpn": [], "torrent": [], "scanner": []}
        for pid, name in _processes():
            if name == "gluetun-entrypoint":
                matches["vpn"].append(pid)
            elif name == "transmission-daemon":
                matches["torrent"].append(pid)
            elif name == "clamscan" and (_pid_stats(pid) or (None,))[0] == os.getpid():
                matches["scanner"].append(pid)
        result = {}
        for label in ("vpn", "torrent"):
            pids = matches[label]
            group = _process_cgroup(pids[0]) if len(pids) == 1 else None
            result[label] = self._entry(label, str(group), _memory_and_cpu(group) if group else None, now)
        for label, pid in (("app", os.getpid()), ("scanner", matches["scanner"][0] if len(matches["scanner"]) == 1 else None)):
            stats = _pid_stats(pid) if pid else None
            result[label] = self._entry(label, str(pid), (stats[2], stats[1] * 1_000_000 / os.sysconf("SC_CLK_TCK")) if stats else None, now)
        result["quarantine"] = _disk_usage(self.root / "quarantine")
        result["snapshots"] = _disk_usage(self.root / "snapshots")
        self.value, self.last = result, now
        return result
