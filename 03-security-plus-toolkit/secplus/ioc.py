"""Hashes files and checks them against a local list of known-bad hashes
(indicators of compromise). Security+ domain 4 (operations) - this is the
basic move behind any "is this file malware" check before you get into
sandboxing or behavioral analysis.
"""

import hashlib
from pathlib import Path

CHUNK_SIZE = 65536


def hash_file(path, algo="sha256"):
    hasher = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def load_ioc_list(path):
    """Format: one hash per line, optionally "hash,label". Lines starting
    with # are comments. Hashes are matched case-insensitively."""
    iocs = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hash_value, _, label = line.partition(",")
        iocs[hash_value.strip().lower()] = label.strip() or "unknown malware"
    return iocs


def check_hash(hash_value, iocs):
    return iocs.get(hash_value.lower())


def scan_directory(dir_path, iocs, algo="sha256"):
    findings = []
    for path in sorted(Path(dir_path).rglob("*")):
        if not path.is_file():
            continue
        file_hash = hash_file(path, algo=algo)
        label = check_hash(file_hash, iocs)
        if label:
            findings.append({"path": str(path), "hash": file_hash, "label": label})
    return findings
