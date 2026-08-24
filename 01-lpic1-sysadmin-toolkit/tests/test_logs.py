from pathlib import Path

from sysadmin_toolkit import logs

FIXTURE = Path(__file__).parent / "fixtures" / "auth.log"


def test_parse_auth_log_counts():
    parsed = logs.parse_auth_log(FIXTURE)
    assert len(parsed["failed"]) == 6
    assert len(parsed["accepted"]) == 2


def test_parse_auth_log_extracts_invalid_user():
    parsed = logs.parse_auth_log(FIXTURE)
    users = {entry["user"] for entry in parsed["failed"]}
    assert "admin" in users
    assert "oracle" in users


def test_summarize_top_offender():
    parsed = logs.parse_auth_log(FIXTURE)
    summary = logs.summarize(parsed)
    assert summary["total_failed"] == 6
    assert summary["top_failed_ips"][0] == ("203.0.113.5", 4)


def test_summarize_top_targeted_user():
    parsed = logs.parse_auth_log(FIXTURE)
    summary = logs.summarize(parsed)
    top_users = dict(summary["top_failed_users"])
    assert top_users["root"] == 3
