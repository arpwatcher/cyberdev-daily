import pytest

from netcalc import vlsm


def test_allocate_classic_example_no_gaps_or_overlaps():
    reqs = [("sales", 50), ("engineering", 20), ("management", 10), ("link-to-isp", 2)]
    allocs = vlsm.allocate("192.168.1.0", 24, reqs)

    assert [a["name"] for a in allocs] == ["sales", "engineering", "management", "link-to-isp"]
    assert allocs[0]["network"] == "192.168.1.0"
    assert allocs[0]["prefix_len"] == 26
    assert allocs[1]["network"] == "192.168.1.64"
    assert allocs[1]["prefix_len"] == 27
    assert allocs[2]["network"] == "192.168.1.96"
    assert allocs[2]["prefix_len"] == 28
    assert allocs[3]["network"] == "192.168.1.112"
    assert allocs[3]["prefix_len"] == 30


def test_allocate_covers_requested_hosts():
    reqs = [("a", 50), ("b", 20), ("c", 10), ("d", 2)]
    allocs = vlsm.allocate("192.168.1.0", 24, reqs)
    for alloc in allocs:
        assert alloc["usable_hosts"] >= alloc["requested_hosts"]


def test_allocate_raises_when_out_of_space():
    with pytest.raises(ValueError):
        vlsm.allocate("192.168.1.0", 28, [("too_big", 100)])


def test_allocate_raises_with_no_requirements():
    with pytest.raises(ValueError):
        vlsm.allocate("192.168.1.0", 24, [])


def test_allocate_no_overlap_between_subnets():
    reqs = [("a", 100), ("b", 50), ("c", 25), ("d", 5)]
    allocs = vlsm.allocate("10.0.0.0", 23, reqs)

    ranges = []
    for alloc in allocs:
        from netcalc.ipaddr import ip_to_int
        ranges.append((ip_to_int(alloc["network"]), ip_to_int(alloc["broadcast"])))

    ranges.sort()
    for i in range(len(ranges) - 1):
        assert ranges[i][1] < ranges[i + 1][0]


def test_utilization_is_between_zero_and_one():
    reqs = [("a", 50), ("b", 20), ("c", 10), ("d", 2)]
    allocs = vlsm.allocate("192.168.1.0", 24, reqs)
    util = vlsm.utilization(allocs)
    assert 0 < util <= 1
