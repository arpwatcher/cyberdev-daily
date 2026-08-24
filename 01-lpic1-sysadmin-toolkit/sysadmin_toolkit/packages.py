"""Package manager detection and installed-package inventory. LPIC-1 topic 102.4/102.5."""

import shutil
import subprocess


def detect_package_manager():
    if shutil.which("dpkg"):
        return "dpkg"
    if shutil.which("rpm"):
        return "rpm"
    return None


def list_installed_packages():
    manager = detect_package_manager()

    if manager == "dpkg":
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"],
            capture_output=True, text=True, check=False,
        )
        packages = []
        for line in out.stdout.splitlines():
            if "\t" not in line:
                continue
            name, _, version = line.partition("\t")
            packages.append({"name": name, "version": version})
        return packages

    if manager == "rpm":
        out = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"],
            capture_output=True, text=True, check=False,
        )
        packages = []
        for line in out.stdout.splitlines():
            if "\t" not in line:
                continue
            name, _, version = line.partition("\t")
            packages.append({"name": name, "version": version})
        return packages

    return []


def list_manual_vs_dependency():
    """Split installed packages into manually requested vs pulled in as a dependency.

    Only supported cleanly on dpkg systems via apt-mark. On rpm systems this
    information isn't tracked the same way, so we return an empty auto list
    and everything falls under manual.
    """
    manager = detect_package_manager()
    all_packages = {p["name"] for p in list_installed_packages()}

    if manager == "dpkg" and shutil.which("apt-mark"):
        out = subprocess.run(
            ["apt-mark", "showmanual"], capture_output=True, text=True, check=False,
        )
        manual = {name.strip() for name in out.stdout.splitlines() if name.strip()}
        manual = manual & all_packages
        auto = all_packages - manual
        return {"manual": sorted(manual), "dependency": sorted(auto)}

    return {"manual": sorted(all_packages), "dependency": []}
