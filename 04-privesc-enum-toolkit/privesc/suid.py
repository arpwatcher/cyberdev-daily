"""Finds SUID/SGID binaries and flags ones outside the expected baseline.
Classic first move in linux privilege escalation enumeration - an unusual
SUID binary is often the fastest way to root on a ctf box.
"""

import os
import stat
from pathlib import Path

# common, expected suid/sgid binaries on a stock debian/ubuntu system -
# anything outside this set on a real box is worth a second look
EXPECTED_SUID = {
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd",
    "/usr/bin/newgrp", "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
}


def find_suid_sgid(root_dir):
    """Walks root_dir looking for files with the setuid or setgid bit set.
    Returns dicts with path and which bit(s) are set."""
    findings = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for name in filenames:
            full_path = Path(dirpath) / name
            try:
                mode = full_path.stat().st_mode
            except OSError:
                continue

            has_suid = bool(mode & stat.S_ISUID)
            has_sgid = bool(mode & stat.S_ISGID)
            if not (has_suid or has_sgid):
                continue

            findings.append({
                "path": str(full_path),
                "suid": has_suid,
                "sgid": has_sgid,
            })

    return findings


def flag_unexpected(findings, expected=None, root_prefix=""):
    """Filter findings down to ones not in the expected baseline. root_prefix
    lets tests point EXPECTED_SUID-style absolute paths at a fixture dir."""
    expected = expected if expected is not None else EXPECTED_SUID
    expected_full = {root_prefix + path for path in expected}
    return [f for f in findings if f["path"] not in expected_full]
