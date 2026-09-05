import stat

from privesc import suid


def test_find_suid_sgid_finds_setuid_file(tmp_path):
    f = tmp_path / "setuid_bin"
    f.write_text("fake binary")
    f.chmod(0o755 | stat.S_ISUID)

    findings = suid.find_suid_sgid(tmp_path)
    assert len(findings) == 1
    assert findings[0]["suid"] is True
    assert findings[0]["sgid"] is False


def test_find_suid_sgid_finds_setgid_file(tmp_path):
    f = tmp_path / "setgid_bin"
    f.write_text("fake binary")
    f.chmod(0o755 | stat.S_ISGID)

    findings = suid.find_suid_sgid(tmp_path)
    assert findings[0]["sgid"] is True
    assert findings[0]["suid"] is False


def test_find_suid_sgid_ignores_normal_files(tmp_path):
    f = tmp_path / "normal_file"
    f.write_text("nothing special")
    f.chmod(0o755)

    assert suid.find_suid_sgid(tmp_path) == []


def test_find_suid_sgid_walks_subdirectories(tmp_path):
    subdir = tmp_path / "usr" / "bin"
    subdir.mkdir(parents=True)
    f = subdir / "deep_suid"
    f.write_text("x")
    f.chmod(0o755 | stat.S_ISUID)

    findings = suid.find_suid_sgid(tmp_path)
    assert len(findings) == 1
    assert findings[0]["path"] == str(f)


def test_flag_unexpected_excludes_baseline(tmp_path):
    expected_dir = tmp_path / "usr" / "bin"
    expected_dir.mkdir(parents=True)
    passwd = expected_dir / "passwd"
    passwd.write_text("x")
    passwd.chmod(0o755 | stat.S_ISUID)

    weird = tmp_path / "tmp" / "weird"
    weird.parent.mkdir(parents=True)
    weird.write_text("x")
    weird.chmod(0o755 | stat.S_ISUID)

    findings = suid.find_suid_sgid(tmp_path)
    unexpected = suid.flag_unexpected(
        findings, expected={"/usr/bin/passwd"}, root_prefix=str(tmp_path)
    )
    assert len(unexpected) == 1
    assert unexpected[0]["path"] == str(weird)
