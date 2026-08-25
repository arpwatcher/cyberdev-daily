"""Process inspection and job control basics via /proc. LPIC-1 topic 103.5."""

import os
from pathlib import Path

PROC_ROOT = Path("/proc")

# see man proc(5) for the /proc/[pid]/stat field layout
STATE_NAMES = {
    "R": "running",
    "S": "sleeping",
    "D": "disk sleep",
    "Z": "zombie",
    "T": "stopped",
    "I": "idle",
}


def _read_stat(pid_dir):
    text = (pid_dir / "stat").read_text()
    # comm can contain spaces/parens itself, so split on the LAST ')' not the first
    comm = text[text.index("(") + 1:text.rindex(")")]
    rest = text[text.rindex(")") + 1:]
    fields = rest.split()
    return {
        "pid": int(pid_dir.name),
        "comm": comm,
        "state": fields[0],
        "ppid": int(fields[1]),
    }


def list_processes():
    processes = []
    for entry in PROC_ROOT.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            processes.append(_read_stat(entry))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return processes


def get_process_info(pid):
    pid_dir = PROC_ROOT / str(pid)
    info = _read_stat(pid_dir)
    info["state_name"] = STATE_NAMES.get(info["state"], info["state"])

    cmdline_path = pid_dir / "cmdline"
    if cmdline_path.exists():
        raw = cmdline_path.read_bytes()
        info["cmdline"] = raw.decode(errors="replace").rstrip("\x00").replace("\x00", " ")
    else:
        info["cmdline"] = ""

    status_path = pid_dir / "status"
    if status_path.exists():
        for line in status_path.read_text().splitlines():
            if line.startswith("VmRSS:"):
                info["rss_kb"] = int(line.split()[1])
                break

    return info


def find_zombies():
    zombies = []
    for proc in list_processes():
        if proc["state"] == "Z":
            zombies.append(proc)
    return zombies


def top_memory_consumers(n=10):
    entries = []
    for proc in list_processes():
        try:
            info = get_process_info(proc["pid"])
        except (FileNotFoundError, ProcessLookupError):
            continue
        if "rss_kb" in info:
            entries.append(info)
    entries.sort(key=lambda p: p["rss_kb"], reverse=True)
    return entries[:n]


def send_signal(pid, sig):
    os.kill(pid, sig)
