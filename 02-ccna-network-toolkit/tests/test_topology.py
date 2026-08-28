from pathlib import Path

from netcalc import topology

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_devices_from_dir_finds_all_configs():
    devices = topology.load_devices_from_dir(FIXTURES)
    assert set(devices) == {"router1", "router2", "router3"}


def test_find_ip_conflicts_detects_duplicate():
    devices = topology.load_devices_from_dir(FIXTURES)
    conflicts = topology.find_ip_conflicts(devices)
    assert len(conflicts) == 1
    assert conflicts[0]["ip_address"] == "192.168.1.1"
    devices_in_conflict = {a["device"] for a in conflicts[0]["assignments"]}
    assert devices_in_conflict == {"router1", "router2"}


def test_find_ip_conflicts_no_conflict_when_ips_unique():
    devices = {
        "a": {"interfaces": [{"name": "eth0", "ip_address": "10.0.0.1", "netmask": "255.255.255.0"}]},
        "b": {"interfaces": [{"name": "eth0", "ip_address": "10.0.0.2", "netmask": "255.255.255.0"}]},
    }
    assert topology.find_ip_conflicts(devices) == []


def test_find_subnet_overlaps_detects_nested_subnet():
    devices = topology.load_devices_from_dir(FIXTURES)
    overlaps = topology.find_subnet_overlaps(devices)
    overlapping_devices = set()
    for o in overlaps:
        overlapping_devices.add(o["a"]["device"])
        overlapping_devices.add(o["b"]["device"])
    assert "router3" in overlapping_devices


def test_find_subnet_overlaps_ignores_shared_lan_subnet():
    devices = {
        "a": {"interfaces": [{"name": "eth0", "ip_address": "10.0.0.1", "netmask": "255.255.255.0"}]},
        "b": {"interfaces": [{"name": "eth0", "ip_address": "10.0.0.2", "netmask": "255.255.255.0"}]},
    }
    assert topology.find_subnet_overlaps(devices) == []


def test_find_subnet_overlaps_no_overlap_for_disjoint_subnets():
    devices = {
        "a": {"interfaces": [{"name": "eth0", "ip_address": "10.0.0.1", "netmask": "255.255.255.0"}]},
        "b": {"interfaces": [{"name": "eth0", "ip_address": "10.0.1.1", "netmask": "255.255.255.0"}]},
    }
    assert topology.find_subnet_overlaps(devices) == []
