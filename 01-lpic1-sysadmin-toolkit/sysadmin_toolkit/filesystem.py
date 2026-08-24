"""Filesystem layout, permissions and disk usage checks. LPIC-1 topic 104."""

import os
import stat
import subprocess
from pathlib import Path

FHS_DIRS = ["/etc", "/var", "/usr", "/home", "/tmp", "/opt"]

# path -> maximum permissive mode allowed (world write/execute etc beyond this is flagged)
SECURITY_SENSITIVE_FILES = {
    "/etc/shadow": 0o640,
    "/etc/passwd": 0o644,
    "/etc/sudoers": 0o440,
    "/etc/ssh/sshd_config": 0o644,
}


def disk_usage_by_fhs():
    usage = {}
    for path in FHS_DIRS:
        if not Path(path).exists():
            continue
        total, used, free = _disk_usage(path)
        usage[path] = {"total_bytes": total, "used_bytes": used, "free_bytes": free}
    return usage


def _disk_usage(path):
    import shutil as _shutil
    result = _shutil.disk_usage(path)
    return result.total, result.used, result.free


def permission_audit(files=None):
    files = files or SECURITY_SENSITIVE_FILES
    findings = []
    for path, max_mode in files.items():
        p = Path(path)
        if not p.exists():
            continue
        actual_mode = stat.S_IMODE(p.stat().st_mode)
        if actual_mode & ~max_mode:
            findings.append({
                "path": path,
                "actual": oct(actual_mode),
                "expected_max": oct(max_mode),
            })
    return findings


def find_broken_symlinks(root):
    broken = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames + dirnames:
            full = Path(dirpath) / name
            if full.is_symlink() and not full.exists():
                broken.append(str(full))
    return broken


def inode_usage():
    out = subprocess.run(["df", "-i"], capture_output=True, text=True, check=False)
    lines = out.stdout.splitlines()
    entries = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        entries.append({
            "filesystem": parts[0],
            "inodes_total": parts[1],
            "inodes_used": parts[2],
            "inodes_free": parts[3],
            "inodes_use_pct": parts[4],
            "mounted_on": parts[5],
        })
    return entries
