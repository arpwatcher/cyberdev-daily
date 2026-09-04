"""Builds the ioc test fixtures: a small directory of sample files plus an
ioc list containing the real hash of one of them. Not part of the test
suite - run manually if it ever needs regenerating:
    python tests/fixtures/make_ioc_fixtures.py
"""

from pathlib import Path

from secplus import ioc

FIXTURES_DIR = Path(__file__).parent
SAMPLES_DIR = FIXTURES_DIR / "ioc_samples"
SAMPLES_DIR.mkdir(exist_ok=True)

(SAMPLES_DIR / "malicious.bin").write_bytes(b"malicious payload content")
(SAMPLES_DIR / "clean.txt").write_bytes(b"just a normal file")

bad_hash = ioc.hash_file(SAMPLES_DIR / "malicious.bin")

ioc_list = FIXTURES_DIR / "sample_iocs.txt"
ioc_list.write_text(
    "# known bad hashes for testing\n"
    f"{bad_hash},trojan.generic\n"
    "0000000000000000000000000000000000000000000000000000000000000000,fake.unrelated\n"
)

print(f"malicious.bin hash: {bad_hash}")
print(f"wrote {ioc_list}")
