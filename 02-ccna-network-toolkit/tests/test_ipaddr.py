import pytest

from netcalc import ipaddr


def test_validate_ip_accepts_valid():
    assert ipaddr.validate_ip("192.168.1.1")
    assert ipaddr.validate_ip("0.0.0.0")
    assert ipaddr.validate_ip("255.255.255.255")


def test_validate_ip_rejects_invalid():
    assert not ipaddr.validate_ip("256.1.1.1")
    assert not ipaddr.validate_ip("1.2.3")
    assert not ipaddr.validate_ip("1.2.3.4.5")
    assert not ipaddr.validate_ip("01.1.1.1")
    assert not ipaddr.validate_ip("a.b.c.d")


def test_ip_to_int_and_back_roundtrip():
    for ip in ["0.0.0.0", "192.168.1.1", "255.255.255.255", "10.0.0.1"]:
        assert ipaddr.int_to_ip(ipaddr.ip_to_int(ip)) == ip


def test_ip_to_int_rejects_invalid():
    with pytest.raises(ValueError):
        ipaddr.ip_to_int("999.1.1.1")


def test_classify_matches_classful_ranges():
    assert ipaddr.classify("10.0.0.1") == "A"
    assert ipaddr.classify("126.0.0.1") == "A"
    assert ipaddr.classify("128.0.0.1") == "B"
    assert ipaddr.classify("172.16.0.1") == "B"
    assert ipaddr.classify("192.168.1.1") == "C"
    assert ipaddr.classify("223.255.255.255") == "C"
    assert ipaddr.classify("224.0.0.1") == "D"
    assert ipaddr.classify("240.0.0.1") == "E"


def test_is_private_rfc1918_ranges():
    assert ipaddr.is_private("10.1.2.3")
    assert ipaddr.is_private("172.16.0.1")
    assert ipaddr.is_private("172.31.255.255")
    assert ipaddr.is_private("192.168.0.1")


def test_is_private_rejects_public_and_boundary():
    assert not ipaddr.is_private("8.8.8.8")
    assert not ipaddr.is_private("172.15.255.255")
    assert not ipaddr.is_private("172.32.0.0")
    assert not ipaddr.is_private("11.0.0.1")
