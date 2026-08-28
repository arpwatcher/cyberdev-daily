from pathlib import Path

from netcalc import config_parser

FIXTURE = Path(__file__).parent / "fixtures" / "router1.cfg"


def test_parse_hostname():
    config = config_parser.parse_config(FIXTURE.read_text())
    assert config["hostname"] == "R1"


def test_parse_interfaces_count():
    config = config_parser.parse_config(FIXTURE.read_text())
    assert len(config["interfaces"]) == 3


def test_parse_interface_ip_and_description():
    config = config_parser.parse_config(FIXTURE.read_text())
    uplink = config["interfaces"][0]
    assert uplink["name"] == "GigabitEthernet0/0"
    assert uplink["ip_address"] == "203.0.113.1"
    assert uplink["netmask"] == "255.255.255.252"
    assert uplink["description"] == "Uplink to ISP"
    assert uplink["shutdown"] is False


def test_parse_shutdown_interface_with_no_ip():
    config = config_parser.parse_config(FIXTURE.read_text())
    unused = config["interfaces"][2]
    assert unused["name"] == "GigabitEthernet0/2"
    assert unused["shutdown"] is True
    assert unused["ip_address"] is None


def test_parse_vlans():
    config = config_parser.parse_config(FIXTURE.read_text())
    assert config["vlans"] == [
        {"id": 10, "name": "SALES"},
        {"id": 20, "name": "ENGINEERING"},
    ]


def test_parse_switchport_vlan():
    text = "interface FastEthernet0/1\n switchport access vlan 30\n!\n"
    config = config_parser.parse_config(text)
    assert config["interfaces"][0]["switchport_vlan"] == 30


def test_parse_empty_config():
    config = config_parser.parse_config("")
    assert config == {"hostname": None, "interfaces": [], "vlans": []}
