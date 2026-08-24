"""Boot process, init system and fstab inspection. LPIC-1 topic 101.2/101.3."""

import os
import subprocess
from pathlib import Path


def detect_firmware():
    return "uefi" if Path("/sys/firmware/efi").is_dir() else "bios"


def detect_init_system():
    comm_path = Path("/proc/1/comm")
    if comm_path.exists():
        comm = comm_path.read_text().strip()
        if "systemd" in comm:
            return "systemd"
        if comm == "init":
            init_link = Path("/sbin/init")
            if init_link.is_symlink():
                target = os.readlink(init_link)
                if "upstart" in target:
                    return "upstart"
            return "sysvinit"
        return comm
    return "unknown"


def get_default_target():
    try:
        out = subprocess.run(
            ["systemctl", "get-default"], capture_output=True, text=True, check=False,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def parse_fstab(path="/etc/fstab"):
    entries = []
    text = Path(path).read_text()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        entry = {
            "device": fields[0],
            "mount_point": fields[1],
            "fs_type": fields[2],
            "options": fields[3].split(","),
        }
        if len(fields) >= 5:
            entry["dump"] = fields[4]
        if len(fields) >= 6:
            entry["pass"] = fields[5]
        entries.append(entry)
    return entries
