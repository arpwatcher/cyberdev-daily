from privesc import path_check


def test_parse_path_splits_on_colon():
    assert path_check.parse_path("/usr/bin:/bin:/usr/local/bin") == [
        "/usr/bin", "/bin", "/usr/local/bin",
    ]


def test_parse_path_ignores_empty_segments():
    assert path_check.parse_path("/usr/bin::/bin") == ["/usr/bin", "/bin"]


def test_find_writable_dirs(tmp_path):
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o777)

    safe = tmp_path / "safe"
    safe.mkdir()
    safe.chmod(0o755)

    result = path_check.find_writable_dirs([str(writable), str(safe)])
    assert result == [str(writable)]


def test_find_hijackable_binaries_flags_writable_dir_before_real_one(tmp_path):
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o777)

    real_bin_dir = tmp_path / "bin"
    real_bin_dir.mkdir()
    (real_bin_dir / "ls").write_text("x")

    dirs = [str(writable), str(real_bin_dir)]
    findings = path_check.find_hijackable_binaries(dirs, ["ls"])
    assert len(findings) == 1
    assert findings[0]["binary"] == "ls"
    assert findings[0]["writable_dir"] == str(writable)


def test_find_hijackable_binaries_safe_when_real_dir_comes_first(tmp_path):
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o777)

    real_bin_dir = tmp_path / "bin"
    real_bin_dir.mkdir()
    (real_bin_dir / "ls").write_text("x")

    dirs = [str(real_bin_dir), str(writable)]
    assert path_check.find_hijackable_binaries(dirs, ["ls"]) == []


def test_find_hijackable_binaries_flags_writable_dir_even_if_binary_missing_elsewhere(tmp_path):
    """A missing binary with a writable dir in PATH is still a real risk -
    nothing stops an attacker from creating it there."""
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o777)

    findings = path_check.find_hijackable_binaries([str(writable)], ["nonexistent_binary"])
    assert len(findings) == 1
