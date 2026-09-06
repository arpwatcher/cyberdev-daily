"""Checks $PATH for privilege escalation via directory order - if a
writable directory comes before the real location of a binary, an attacker
can drop a malicious file with that name and have it run instead, for
anyone or any script that calls the binary without an absolute path.
"""

import stat
from pathlib import Path


def parse_path(path_str):
    return [p for p in path_str.split(":") if p]


def find_writable_dirs(dirs):
    writable = []
    for d in dirs:
        try:
            mode = Path(d).stat().st_mode
        except OSError:
            continue
        if mode & stat.S_IWOTH:
            writable.append(d)
    return writable


def find_hijackable_binaries(dirs, binary_names):
    """For each binary, walk the PATH dirs in order. If a writable
    directory is reached before a directory that actually contains the
    binary, that binary is hijackable."""
    findings = []
    for name in binary_names:
        for d in dirs:
            dir_path = Path(d)
            try:
                mode = dir_path.stat().st_mode
            except OSError:
                continue

            if (dir_path / name).exists():
                break
            if mode & stat.S_IWOTH:
                findings.append({"binary": name, "writable_dir": d})
                break

    return findings
