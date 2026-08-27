import pytest

from netcalc import subnetting


def test_cidr_to_mask_common_values():
    assert subnetting.cidr_to_mask(24) == "255.255.255.0"
    assert subnetting.cidr_to_mask(26) == "255.255.255.192"
    assert subnetting.cidr_to_mask(0) == "0.0.0.0"
    assert subnetting.cidr_to_mask(32) == "255.255.255.255"


def test_cidr_to_mask_rejects_out_of_range():
    with pytest.raises(ValueError):
        subnetting.cidr_to_mask(33)


def test_mask_to_cidr_roundtrip():
    for prefix in [8, 16, 24, 26, 30, 32]:
        mask = subnetting.cidr_to_mask(prefix)
        assert subnetting.mask_to_cidr(mask) == prefix


def test_mask_to_cidr_rejects_noncontiguous():
    with pytest.raises(ValueError):
        subnetting.mask_to_cidr("255.255.254.1")


def test_wildcard_mask():
    assert subnetting.wildcard_mask(24) == "0.0.0.255"
    assert subnetting.wildcard_mask(26) == "0.0.0.63"


def test_subnet_info_slash_26():
    info = subnetting.subnet_info("192.168.1.100", 26)
    assert info["network"] == "192.168.1.64"
    assert info["broadcast"] == "192.168.1.127"
    assert info["first_host"] == "192.168.1.65"
    assert info["last_host"] == "192.168.1.126"
    assert info["usable_hosts"] == 62
    assert info["total_hosts"] == 64


def test_subnet_info_slash_24():
    info = subnetting.subnet_info("10.0.5.200", 24)
    assert info["network"] == "10.0.5.0"
    assert info["broadcast"] == "10.0.5.255"
    assert info["usable_hosts"] == 254


def test_subnet_info_slash_31_and_32_have_no_usable_hosts():
    assert subnetting.subnet_info("10.0.0.0", 31)["usable_hosts"] == 0
    assert subnetting.subnet_info("10.0.0.1", 32)["usable_hosts"] == 0
    assert subnetting.subnet_info("10.0.0.1", 32)["first_host"] is None


def test_same_subnet():
    assert subnetting.same_subnet("192.168.1.10", "192.168.1.50", 26)
    assert not subnetting.same_subnet("192.168.1.10", "192.168.1.70", 26)


def test_hosts_to_prefix():
    assert subnetting.hosts_to_prefix(50) == 26
    assert subnetting.hosts_to_prefix(2) == 30
    assert subnetting.hosts_to_prefix(1) == 30
    assert subnetting.hosts_to_prefix(254) == 24
    assert subnetting.hosts_to_prefix(255) == 23


def test_hosts_to_prefix_rejects_zero():
    with pytest.raises(ValueError):
        subnetting.hosts_to_prefix(0)
