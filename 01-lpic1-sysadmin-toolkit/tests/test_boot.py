from pathlib import Path

from sysadmin_toolkit import boot

FIXTURE = Path(__file__).parent / "fixtures" / "fstab"


def test_parse_fstab_entry_count():
    entries = boot.parse_fstab(FIXTURE)
    assert len(entries) == 4


def test_parse_fstab_fields():
    entries = boot.parse_fstab(FIXTURE)
    root = next(e for e in entries if e["mount_point"] == "/")
    assert root["fs_type"] == "ext4"
    assert root["device"] == "UUID=1111-2222"


def test_parse_fstab_options_split():
    entries = boot.parse_fstab(FIXTURE)
    tmp = next(e for e in entries if e["mount_point"] == "/tmp")
    assert tmp["options"] == ["defaults", "noatime"]


def test_parse_fstab_skips_comments():
    entries = boot.parse_fstab(FIXTURE)
    devices = [e["device"] for e in entries]
    assert all(not d.startswith("#") for d in devices)
