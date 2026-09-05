from privesc import cron


def test_parse_system_crontab_fields():
    text = "*/5 * * * * root /usr/local/bin/backup.sh\n"
    jobs = cron.parse_system_crontab(text)
    assert len(jobs) == 1
    assert jobs[0]["minute"] == "*/5"
    assert jobs[0]["user"] == "root"
    assert jobs[0]["command"] == "/usr/local/bin/backup.sh"


def test_parse_system_crontab_skips_comments():
    text = "# a comment\n*/5 * * * * root /bin/true\n"
    jobs = cron.parse_system_crontab(text)
    assert len(jobs) == 1


def test_parse_user_crontab_no_user_field():
    text = "0 2 * * * /home/user/cleanup.sh\n"
    jobs = cron.parse_user_crontab(text)
    assert len(jobs) == 1
    assert jobs[0]["user"] is None
    assert jobs[0]["command"] == "/home/user/cleanup.sh"


def test_find_writable_targets_flags_world_writable_script(tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/bash\necho hi\n")
    script.chmod(0o777)

    jobs = [{"minute": "*", "hour": "*", "dom": "*", "month": "*", "dow": "*",
             "user": "root", "command": str(script)}]
    findings = cron.find_writable_targets(jobs)
    assert len(findings) == 1
    assert findings[0]["reason"] == "script itself is world-writable"


def test_find_writable_targets_flags_writable_directory(tmp_path):
    writable_dir = tmp_path / "scripts"
    writable_dir.mkdir()
    writable_dir.chmod(0o777)
    script = writable_dir / "job.sh"
    script.write_text("x")
    script.chmod(0o755)

    jobs = [{"minute": "*", "hour": "*", "dom": "*", "month": "*", "dow": "*",
             "user": "root", "command": str(script)}]
    findings = cron.find_writable_targets(jobs)
    assert len(findings) == 1
    assert findings[0]["reason"] == "containing directory is world-writable"


def test_find_writable_targets_ignores_safe_script(tmp_path):
    script = tmp_path / "safe.sh"
    script.write_text("x")
    script.chmod(0o755)

    jobs = [{"minute": "*", "hour": "*", "dom": "*", "month": "*", "dow": "*",
             "user": "root", "command": str(script)}]
    assert cron.find_writable_targets(jobs) == []


def test_find_writable_targets_ignores_commands_without_path():
    jobs = [{"minute": "*", "hour": "*", "dom": "*", "month": "*", "dow": "*",
             "user": "root", "command": "echo hello"}]
    assert cron.find_writable_targets(jobs) == []
