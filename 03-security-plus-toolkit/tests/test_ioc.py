import hashlib
from pathlib import Path

from secplus import ioc

FIXTURES = Path(__file__).parent / "fixtures"
IOC_LIST = FIXTURES / "sample_iocs.txt"
SAMPLES_DIR = FIXTURES / "ioc_samples"


def test_hash_file_matches_hashlib(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"some content to hash")

    assert ioc.hash_file(f) == hashlib.sha256(b"some content to hash").hexdigest()


def test_hash_file_supports_other_algorithms(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"some content")

    assert ioc.hash_file(f, algo="md5") == hashlib.md5(b"some content").hexdigest()


def test_load_ioc_list_parses_hash_and_label():
    iocs = ioc.load_ioc_list(IOC_LIST)
    assert iocs["49c2d25a459241b1ae54b2c4e878da19d0b28c07ff95b5cdf01a93c7aa337e19"] == "trojan.generic"


def test_load_ioc_list_skips_comments():
    iocs = ioc.load_ioc_list(IOC_LIST)
    assert len(iocs) == 2


def test_check_hash_case_insensitive():
    iocs = {"abc123": "malware.x"}
    assert ioc.check_hash("ABC123", iocs) == "malware.x"


def test_check_hash_no_match_returns_none():
    iocs = {"abc123": "malware.x"}
    assert ioc.check_hash("def456", iocs) is None


def test_scan_directory_finds_known_bad_file():
    iocs = ioc.load_ioc_list(IOC_LIST)
    findings = ioc.scan_directory(SAMPLES_DIR, iocs)
    matched_paths = {f["path"] for f in findings}
    assert any("malicious.bin" in p for p in matched_paths)


def test_scan_directory_does_not_flag_clean_files():
    iocs = ioc.load_ioc_list(IOC_LIST)
    findings = ioc.scan_directory(SAMPLES_DIR, iocs)
    matched_paths = {f["path"] for f in findings}
    assert not any("clean.txt" in p for p in matched_paths)


def test_scan_directory_includes_label():
    iocs = ioc.load_ioc_list(IOC_LIST)
    findings = ioc.scan_directory(SAMPLES_DIR, iocs)
    hit = next(f for f in findings if "malicious.bin" in f["path"])
    assert hit["label"] == "trojan.generic"
