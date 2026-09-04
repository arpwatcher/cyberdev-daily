from pathlib import Path

from secplus import firewall

FIXTURE = Path(__file__).parent / "fixtures" / "sample_iptables.rules"


def test_parse_config_policies():
    config = firewall.parse_config(FIXTURE.read_text())
    assert config["policies"] == {"INPUT": "ACCEPT", "FORWARD": "DROP", "OUTPUT": "ACCEPT"}


def test_parse_config_rule_count():
    config = firewall.parse_config(FIXTURE.read_text())
    assert len(config["rules"]) == 6


def test_parse_config_rule_fields():
    config = firewall.parse_config(FIXTURE.read_text())
    ssh_rule = config["rules"][0]
    assert ssh_rule["proto"] == "tcp"
    assert ssh_rule["dport"] == 22
    assert ssh_rule["jump"] == "ACCEPT"
    assert ssh_rule["src"] is None


def test_parse_config_rule_with_source():
    config = firewall.parse_config(FIXTURE.read_text())
    mysql_rule = next(r for r in config["rules"] if r["dport"] == 3306)
    assert mysql_rule["src"] == "10.0.0.0/24"


def test_find_permissive_default_policies():
    config = firewall.parse_config(FIXTURE.read_text())
    findings = firewall.find_permissive_default_policies(config)
    assert findings == [{"chain": "INPUT", "policy": "ACCEPT"}]


def test_find_exposed_sensitive_ports_flags_unrestricted():
    config = firewall.parse_config(FIXTURE.read_text())
    findings = firewall.find_exposed_sensitive_ports(config)
    ports = {f["port"] for f in findings}
    assert ports == {22, 23, 3389}


def test_find_exposed_sensitive_ports_excludes_restricted_source():
    config = firewall.parse_config(FIXTURE.read_text())
    findings = firewall.find_exposed_sensitive_ports(config)
    assert not any(f["port"] == 3306 for f in findings)


def test_find_cleartext_services():
    config = firewall.parse_config(FIXTURE.read_text())
    findings = firewall.find_cleartext_services(config)
    assert findings == [{"chain": "INPUT", "port": 23, "service": "telnet"}]


def test_audit_combines_all_checks():
    config = firewall.parse_config(FIXTURE.read_text())
    result = firewall.audit(config)
    assert "permissive_defaults" in result
    assert "exposed_sensitive_ports" in result
    assert "cleartext_services" in result


def test_parse_config_ignores_comments_and_headers():
    config = firewall.parse_config(FIXTURE.read_text())
    for rule in config["rules"]:
        assert rule["chain"] == "INPUT"
