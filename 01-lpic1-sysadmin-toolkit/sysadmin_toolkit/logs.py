"""Auth log parsing for SSH login attempts. LPIC-1 topic 107/108 adjacent, useful for
day to day sysadmin work regardless of exam mapping."""

import re
from collections import Counter
from pathlib import Path

FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")


def parse_auth_log(path):
    text = Path(path).read_text()
    failed = []
    accepted = []

    for line in text.splitlines():
        match = FAILED_RE.search(line)
        if match:
            failed.append({"user": match.group(1), "ip": match.group(2)})
            continue
        match = ACCEPTED_RE.search(line)
        if match:
            accepted.append({"user": match.group(1), "ip": match.group(2)})

    return {"failed": failed, "accepted": accepted}


def summarize(parsed, top_n=5):
    failed_ips = Counter(entry["ip"] for entry in parsed["failed"])
    failed_users = Counter(entry["user"] for entry in parsed["failed"])

    return {
        "total_failed": len(parsed["failed"]),
        "total_accepted": len(parsed["accepted"]),
        "top_failed_ips": failed_ips.most_common(top_n),
        "top_failed_users": failed_users.most_common(top_n),
    }
