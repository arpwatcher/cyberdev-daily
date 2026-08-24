import os
import stat

from sysadmin_toolkit import filesystem


def test_permission_audit_flags_world_readable_shadow(tmp_path):
    fake_shadow = tmp_path / "shadow"
    fake_shadow.write_text("root:!:19000:0:99999:7:::\n")
    fake_shadow.chmod(0o644)

    findings = filesystem.permission_audit({str(fake_shadow): 0o640})
    assert len(findings) == 1
    assert findings[0]["path"] == str(fake_shadow)


def test_permission_audit_passes_correct_mode(tmp_path):
    fake_shadow = tmp_path / "shadow"
    fake_shadow.write_text("root:!:19000:0:99999:7:::\n")
    fake_shadow.chmod(0o640)

    findings = filesystem.permission_audit({str(fake_shadow): 0o640})
    assert findings == []


def test_find_broken_symlinks(tmp_path):
    target = tmp_path / "real_file"
    target.write_text("data")
    good_link = tmp_path / "good_link"
    good_link.symlink_to(target)

    broken_link = tmp_path / "broken_link"
    broken_link.symlink_to(tmp_path / "does_not_exist")

    broken = filesystem.find_broken_symlinks(tmp_path)
    assert str(broken_link) in broken
    assert str(good_link) not in broken
