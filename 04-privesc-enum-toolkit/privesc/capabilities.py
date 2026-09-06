"""Parses `getcap -r /` style output and flags binaries carrying a
capability that amounts to privilege escalation - cap_setuid lets a binary
change its own uid outright, which is effectively a suid bit without the
suid bit, and gets missed by a plain suid/sgid scan.
"""

import re

LINE_RE = re.compile(r"^(?P<path>\S+)\s+(?P<caps>\S+)$")

DANGEROUS_CAPS = {
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module",
}


def parse_getcap_output(text):
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = LINE_RE.match(line)
        if not match:
            continue

        # the capability list is separated from the eip flags by "=" or "+"
        # depending on getcap version (e.g. "cap_net_raw=ep" vs "cap_setuid+eip")
        caps_field = match.group("caps")
        cap_list = re.split(r"[=+]", caps_field, maxsplit=1)[0]
        cap_names = [c.lower() for c in cap_list.split(",")]
        entries.append({"path": match.group("path"), "capabilities": cap_names})

    return entries


def flag_dangerous(entries):
    findings = []
    for entry in entries:
        dangerous = [c for c in entry["capabilities"] if c in DANGEROUS_CAPS]
        if dangerous:
            findings.append({"path": entry["path"], "dangerous_caps": dangerous})
    return findings
