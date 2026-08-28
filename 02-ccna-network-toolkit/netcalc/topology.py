"""Cross-device checks over a set of parsed configs: duplicate IPs and
subnets that overlap when they shouldn't.
"""

from collections import defaultdict
from pathlib import Path

from netcalc import config_parser, subnetting
from netcalc.ipaddr import ip_to_int


def load_devices_from_dir(dir_path):
    """Parse every config file in a directory, keyed by filename stem."""
    devices = {}
    for path in sorted(Path(dir_path).glob("*.cfg")):
        devices[path.stem] = config_parser.parse_config(path.read_text())
    return devices


def _interface_ip_entries(devices):
    entries = []
    for device_name, config in devices.items():
        for iface in config["interfaces"]:
            if iface["ip_address"] and iface["netmask"]:
                entries.append({
                    "device": device_name,
                    "interface": iface["name"],
                    "ip_address": iface["ip_address"],
                    "netmask": iface["netmask"],
                })
    return entries


def find_ip_conflicts(devices):
    """Same ip address assigned on interfaces belonging to different devices."""
    entries = _interface_ip_entries(devices)
    by_ip = defaultdict(list)
    for entry in entries:
        by_ip[entry["ip_address"]].append(entry)

    conflicts = []
    for ip_address, assignments in by_ip.items():
        distinct_devices = {a["device"] for a in assignments}
        if len(distinct_devices) > 1:
            conflicts.append({"ip_address": ip_address, "assignments": assignments})
    return conflicts


def find_subnet_overlaps(devices):
    """Interfaces on different subnets whose address ranges overlap - a real
    addressing mistake, as opposed to two interfaces correctly sharing the
    same subnet on a common LAN segment."""
    entries = _interface_ip_entries(devices)

    ranged = []
    for entry in entries:
        prefix_len = subnetting.mask_to_cidr(entry["netmask"])
        info = subnetting.subnet_info(entry["ip_address"], prefix_len)
        ranged.append({
            **entry,
            "prefix_len": prefix_len,
            "network": info["network"],
            "broadcast": info["broadcast"],
        })

    overlaps = []
    for i in range(len(ranged)):
        for j in range(i + 1, len(ranged)):
            a, b = ranged[i], ranged[j]
            if a["network"] == b["network"] and a["prefix_len"] == b["prefix_len"]:
                continue

            a_start, a_end = ip_to_int(a["network"]), ip_to_int(a["broadcast"])
            b_start, b_end = ip_to_int(b["network"]), ip_to_int(b["broadcast"])
            if a_start <= b_end and b_start <= a_end:
                overlaps.append({"a": a, "b": b})

    return overlaps
