from privesc import capabilities


def test_parse_equals_separator_format():
    entries = capabilities.parse_getcap_output("/usr/bin/ping cap_net_raw=ep\n")
    assert entries[0]["capabilities"] == ["cap_net_raw"]


def test_parse_plus_separator_format():
    entries = capabilities.parse_getcap_output("/usr/bin/python3.9 cap_setuid+eip\n")
    assert entries[0]["capabilities"] == ["cap_setuid"]


def test_parse_multiple_capabilities_comma_separated():
    entries = capabilities.parse_getcap_output("/usr/bin/perl cap_setuid,cap_setgid+eip\n")
    assert entries[0]["capabilities"] == ["cap_setuid", "cap_setgid"]


def test_parse_multiple_lines():
    text = "/usr/bin/ping cap_net_raw=ep\n/usr/bin/perl cap_setuid+eip\n"
    entries = capabilities.parse_getcap_output(text)
    assert len(entries) == 2


def test_parse_skips_blank_lines():
    text = "/usr/bin/ping cap_net_raw=ep\n\n\n/usr/bin/perl cap_setuid+eip\n"
    entries = capabilities.parse_getcap_output(text)
    assert len(entries) == 2


def test_flag_dangerous_finds_setuid():
    entries = [{"path": "/usr/bin/perl", "capabilities": ["cap_setuid"]}]
    findings = capabilities.flag_dangerous(entries)
    assert findings == [{"path": "/usr/bin/perl", "dangerous_caps": ["cap_setuid"]}]


def test_flag_dangerous_ignores_harmless_capability():
    entries = [{"path": "/usr/bin/ping", "capabilities": ["cap_net_raw"]}]
    assert capabilities.flag_dangerous(entries) == []


def test_flag_dangerous_multiple_dangerous_caps_on_one_binary():
    entries = [{"path": "/usr/bin/perl", "capabilities": ["cap_setuid", "cap_setgid"]}]
    findings = capabilities.flag_dangerous(entries)
    assert findings[0]["dangerous_caps"] == ["cap_setuid", "cap_setgid"]
