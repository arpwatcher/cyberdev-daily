"""Parses `sudo -l` style output and flags sudo permissions that are a well
known path to root - binaries with a documented shell escape (gtfobins
style) and the blanket "run anything" rule.
"""

import re

ENTRY_RE = re.compile(r"^\s*\((?P<runas>[^)]+)\)\s*(?P<nopasswd>NOPASSWD:\s*)?(?P<command>.+?)\s*$")

# binaries with a well known sudo shell-escape technique - not exhaustive,
# just the ones that show up constantly on ctf boxes and real audits
DANGEROUS_BINARIES = {
    "vim", "vi", "less", "more", "man", "awk", "find", "python", "python3",
    "perl", "ruby", "nmap", "tar", "zip", "gdb", "git", "sed", "nc", "ncat",
    "socat", "env", "make", "ftp", "gcc", "cp", "mv",
}


def parse_sudo_l(text):
    entries = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Matching", "User", "Sudoers")):
            continue
        match = ENTRY_RE.match(line)
        if not match:
            continue
        entries.append({
            "runas": match.group("runas"),
            "nopasswd": bool(match.group("nopasswd")),
            "command": match.group("command"),
        })
    return entries


def _binary_name(command):
    first_token = command.split()[0] if command.split() else ""
    return first_token.rsplit("/", 1)[-1]


def flag_blanket_all(entries):
    return [e for e in entries if e["command"].strip() == "ALL"]


def flag_dangerous_binaries(entries):
    findings = []
    for entry in entries:
        if entry["command"].strip() == "ALL":
            continue
        name = _binary_name(entry["command"])
        if name in DANGEROUS_BINARIES:
            findings.append({**entry, "binary": name})
    return findings


def audit(text):
    entries = parse_sudo_l(text)
    return {
        "entries": entries,
        "blanket_all": flag_blanket_all(entries),
        "dangerous_binaries": flag_dangerous_binaries(entries),
    }
