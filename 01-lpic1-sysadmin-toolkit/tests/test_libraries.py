import pytest

from sysadmin_toolkit import libraries


def test_parse_ldconfig_cache():
    text = (
        "1234 libs found in cache `/etc/ld.so.cache'\n"
        "\tlibz.so.1 (libc6,x86-64) => /lib/x86_64-linux-gnu/libz.so.1\n"
        "\tlibc.so.6 (libc6,x86-64, OS ABI: Linux 3.2.0) => /lib/x86_64-linux-gnu/libc.so.6\n"
    )
    entries = libraries.parse_ldconfig_cache(text)
    assert len(entries) == 2
    assert entries[0]["soname"] == "libz.so.1"
    assert entries[0]["path"] == "/lib/x86_64-linux-gnu/libz.so.1"


def test_search_library_case_insensitive():
    cache = [
        {"soname": "libZip.so.4", "tags": "libc6", "path": "/lib/libZip.so.4"},
        {"soname": "libssl.so.3", "tags": "libc6", "path": "/lib/libssl.so.3"},
    ]
    results = libraries.search_library("zip", cache=cache)
    assert len(results) == 1
    assert results[0]["soname"] == "libZip.so.4"


def test_check_dependencies_missing_binary(tmp_path):
    with pytest.raises(FileNotFoundError):
        libraries.check_dependencies(tmp_path / "does_not_exist")


def test_find_missing_dependencies_filters_resolved(monkeypatch):
    def fake_check(binary_path):
        return [
            {"name": "libc.so.6", "path": "/lib/libc.so.6", "resolved": True},
            {"name": "libfoo.so.1", "path": None, "resolved": False},
        ]

    monkeypatch.setattr(libraries, "check_dependencies", fake_check)
    missing = libraries.find_missing_dependencies("/bin/whatever")
    assert len(missing) == 1
    assert missing[0]["name"] == "libfoo.so.1"


def test_get_search_paths_reads_conf(tmp_path):
    conf = tmp_path / "ld.so.conf"
    conf.write_text("/usr/local/lib\n# comment\n/does/not/exist\n")

    paths = libraries.get_search_paths(conf)
    by_path = {p["path"]: p["exists"] for p in paths}
    assert by_path["/does/not/exist"] is False
