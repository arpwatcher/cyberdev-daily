"""CPU, memory and bus device inspection. LPIC-1 topic 101.1 (hardware settings)."""

import re
import shutil
import subprocess
from pathlib import Path


def get_cpu_info():
    text = Path("/proc/cpuinfo").read_text()
    blocks = text.strip().split("\n\n")
    model = None
    physical_ids = set()
    logical_count = 0

    for block in blocks:
        fields = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            fields[key.strip()] = val.strip()
        if "processor" not in fields:
            continue
        logical_count += 1
        if model is None:
            model = fields.get("model name")
        if "physical id" in fields:
            physical_ids.add(fields["physical id"])

    return {
        "model": model or "unknown",
        "logical_cpus": logical_count,
        "physical_packages": len(physical_ids) or 1,
    }


def get_memory_info():
    text = Path("/proc/meminfo").read_text()
    info = {}
    for line in text.splitlines():
        key, _, val = line.partition(":")
        val = val.strip()
        if val.endswith("kB"):
            info[key] = int(val[:-2].strip()) * 1024
    return {
        "total_bytes": info.get("MemTotal", 0),
        "free_bytes": info.get("MemFree", 0),
        "available_bytes": info.get("MemAvailable", info.get("MemFree", 0)),
        "swap_total_bytes": info.get("SwapTotal", 0),
        "swap_free_bytes": info.get("SwapFree", 0),
    }


def list_pci_devices():
    if shutil.which("lspci"):
        out = subprocess.run(["lspci"], capture_output=True, text=True, check=False)
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]

    devices = []
    pci_root = Path("/sys/bus/pci/devices")
    if pci_root.is_dir():
        for dev in sorted(pci_root.iterdir()):
            class_file = dev / "class"
            if class_file.exists():
                devices.append(f"{dev.name} class={class_file.read_text().strip()}")
    return devices


def list_usb_devices():
    if shutil.which("lsusb"):
        out = subprocess.run(["lsusb"], capture_output=True, text=True, check=False)
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]

    devices = []
    usb_root = Path("/sys/bus/usb/devices")
    if usb_root.is_dir():
        for dev in sorted(usb_root.iterdir()):
            product_file = dev / "product"
            if product_file.exists():
                devices.append(f"{dev.name}: {product_file.read_text().strip()}")
    return devices


def list_block_devices():
    devices = []
    partitions = Path("/proc/partitions").read_text().splitlines()
    for line in partitions[2:]:
        parts = line.split()
        if len(parts) != 4:
            continue
        major, minor, blocks, name = parts
        if re.match(r"^(loop|ram)", name):
            continue
        size_mb = int(blocks) / 1024
        devices.append({"name": name, "size_mb": round(size_mb, 1)})
    return devices
