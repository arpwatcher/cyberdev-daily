from pathlib import Path

from privesc import sudo_perms

FIXTURE = Path(__file__).parent / "fixtures" / "sample_sudo_l.txt"


def test_parse_sudo_l_entry_count():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    assert len(entries) == 4


def test_parse_sudo_l_nopasswd_flag():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    vim_entry = next(e for e in entries if "vim" in e["command"])
    assert vim_entry["nopasswd"] is True


def test_parse_sudo_l_without_nopasswd():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    systemctl_entry = next(e for e in entries if "systemctl" in e["command"])
    assert systemctl_entry["nopasswd"] is False


def test_parse_sudo_l_skips_header_lines():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    for entry in entries:
        assert "Defaults" not in entry["command"]


def test_flag_blanket_all():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    findings = sudo_perms.flag_blanket_all(entries)
    assert len(findings) == 1
    assert findings[0]["runas"] == "ALL : ALL"


def test_flag_dangerous_binaries():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    findings = sudo_perms.flag_dangerous_binaries(entries)
    binaries = {f["binary"] for f in findings}
    assert binaries == {"vim", "find"}


def test_flag_dangerous_binaries_ignores_safe_commands():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    findings = sudo_perms.flag_dangerous_binaries(entries)
    assert not any("systemctl" in f["command"] for f in findings)


def test_flag_dangerous_binaries_excludes_blanket_all():
    entries = sudo_perms.parse_sudo_l(FIXTURE.read_text())
    findings = sudo_perms.flag_dangerous_binaries(entries)
    assert not any(f["command"] == "ALL" for f in findings)


def test_audit_combines_everything():
    result = sudo_perms.audit(FIXTURE.read_text())
    assert len(result["entries"]) == 4
    assert len(result["blanket_all"]) == 1
    assert len(result["dangerous_binaries"]) == 2
