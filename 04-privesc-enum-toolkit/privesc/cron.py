"""Parses crontab entries and flags jobs that execute a world-writable
script (or a script sitting in a world-writable directory) - if you can
edit the file another user's cron job runs, you escalate to that user
the next time the job fires.
"""

import re
import stat
from pathlib import Path

SYSTEM_CRON_RE = re.compile(
    r"^\s*(?P<minute>\S+)\s+(?P<hour>\S+)\s+(?P<dom>\S+)\s+(?P<month>\S+)\s+(?P<dow>\S+)\s+"
    r"(?P<user>\S+)\s+(?P<command>.+)$"
)
USER_CRON_RE = re.compile(
    r"^\s*(?P<minute>\S+)\s+(?P<hour>\S+)\s+(?P<dom>\S+)\s+(?P<month>\S+)\s+(?P<dow>\S+)\s+"
    r"(?P<command>.+)$"
)


def parse_system_crontab(text):
    """/etc/crontab style: min hour dom month dow user command."""
    jobs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = SYSTEM_CRON_RE.match(line)
        if match:
            jobs.append(match.groupdict())
    return jobs


def parse_user_crontab(text):
    """crontab -l style: min hour dom month dow command, no user field."""
    jobs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = USER_CRON_RE.match(line)
        if match:
            job = match.groupdict()
            job["user"] = None
            jobs.append(job)
    return jobs


def _extract_script_path(command):
    for token in command.split():
        if token.startswith("/"):
            return token
    return None


def find_writable_targets(jobs):
    findings = []
    for job in jobs:
        script_path = _extract_script_path(job["command"])
        if not script_path:
            continue

        path = Path(script_path)
        reason = None
        try:
            if path.exists() and path.stat().st_mode & stat.S_IWOTH:
                reason = "script itself is world-writable"
            elif path.parent.exists() and path.parent.stat().st_mode & stat.S_IWOTH:
                reason = "containing directory is world-writable"
        except OSError:
            continue

        if reason:
            findings.append({**job, "script_path": script_path, "reason": reason})

    return findings
