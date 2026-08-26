"""Shared library dependency inspection via ldd/ldconfig. LPIC-1 topic 102.3."""

import re
import shutil
import subprocess
from pathlib import Path

LDD_LINE_RE = re.compile(
    r"^\s*(?P<name>\S+)"
    r"(?:\s*=>\s*(?P<path>[^\s(]+))?"
    r"\s*(?:\((?P<addr>0x[0-9a-f]+)\))?\s*$"
)


def check_dependencies(binary_path):
    """Run ldd on a binary and return its shared library dependencies.

    Each entry has name, path (None if not resolved) and resolved (bool).
    Raises FileNotFoundError if the binary doesn't exist, RuntimeError if
    ldd itself fails (e.g. not a dynamic executable).
    """
    binary_path = str(binary_path)
    if not Path(binary_path).exists():
        raise FileNotFoundError(binary_path)

    out = subprocess.run(["ldd", binary_path], capture_output=True, text=True, check=False)
    if out.returncode != 0 and "not a dynamic executable" in out.stderr:
        raise RuntimeError(f"{binary_path} is not a dynamic executable")

    deps = []
    for line in out.stdout.splitlines():
        if "not found" in line:
            match = LDD_LINE_RE.match(line)
            name = match.group("name") if match else line.strip()
            deps.append({"name": name, "path": None, "resolved": False})
            continue
        match = LDD_LINE_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        path = match.group("path")
        # entries with no "=>" are either the vdso (no real file) or an absolute
        # path to the dynamic linker itself, printed directly instead of via "=>"
        if path is None and name.startswith("/"):
            path = name
        resolved = path is not None or "vdso" in name
        deps.append({"name": name, "path": path, "resolved": resolved})
    return deps


def find_missing_dependencies(binary_path):
    return [d for d in check_dependencies(binary_path) if not d["resolved"]]


LDCONFIG_LINE_RE = re.compile(r"^\s*(?P<soname>\S+)\s*\((?P<tags>[^)]*)\)\s*=>\s*(?P<path>\S+)\s*$")


def parse_ldconfig_cache(text):
    entries = []
    for line in text.splitlines():
        match = LDCONFIG_LINE_RE.match(line)
        if not match:
            continue
        entries.append({
            "soname": match.group("soname"),
            "tags": match.group("tags"),
            "path": match.group("path"),
        })
    return entries


def list_ldconfig_cache():
    if not shutil.which("ldconfig"):
        return []
    out = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, check=False)
    return parse_ldconfig_cache(out.stdout)


def search_library(name, cache=None):
    cache = cache if cache is not None else list_ldconfig_cache()
    name_lower = name.lower()
    return [entry for entry in cache if name_lower in entry["soname"].lower()]


def get_search_paths(conf_path="/etc/ld.so.conf"):
    """Read ld.so.conf, following include directives, and return configured
    library search directories along with which ones don't actually exist."""
    conf_path = Path(conf_path)
    paths = []
    if not conf_path.exists():
        return paths

    for line in conf_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("include "):
            pattern = line[len("include "):].strip()
            base = conf_path.parent
            for included in sorted(base.glob(pattern) if "/" not in pattern else Path("/").glob(pattern.lstrip("/"))):
                paths.extend(get_search_paths(included))
            continue
        paths.append({"path": line, "exists": Path(line).is_dir()})

    return paths
