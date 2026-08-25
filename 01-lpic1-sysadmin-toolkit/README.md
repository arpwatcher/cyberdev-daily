# lpic1-sysadmin-toolkit

Command line toolkit for inspecting a Linux box, built while going through LPIC-1 101-500
material. Each module lines up with a section of the exam objectives, so writing it doubled
as revision.

- `hardware.py` - CPU and memory info from `/proc`, PCI/USB device listing (falls back to
  `/sys` when `lspci`/`lsusb` aren't installed), block device sizes
- `packages.py` - detects dpkg or rpm, lists installed packages, splits manually installed
  from dependency-pulled packages via `apt-mark`
- `boot.py` - BIOS vs UEFI detection, init system detection, default systemd target,
  `/etc/fstab` parsing
- `filesystem.py` - disk usage per FHS directory, permission audit against a set of
  security sensitive files, broken symlink finder, inode usage
- `logs.py` - parses SSH auth logs for failed/accepted login attempts, summarizes the
  worst offending IPs and usernames
- `processes.py` - process listing and info straight from `/proc`, zombie process
  finder, top memory consumers, basic signal sending

## Usage

```
cd 01-lpic1-sysadmin-toolkit
python -m sysadmin_toolkit.cli hardware
python -m sysadmin_toolkit.cli packages
python -m sysadmin_toolkit.cli boot
python -m sysadmin_toolkit.cli fs --symlink-root /etc
python -m sysadmin_toolkit.cli logs --log-path /var/log/auth.log
python -m sysadmin_toolkit.cli processes --top 10
python -m sysadmin_toolkit.cli all
```

## Tests

```
pip install pytest
pytest
```

Tests run against fixture files in `tests/fixtures/` (a sample auth.log and fstab), not the
real system, so they behave the same on any machine. The `fs` and `hardware` commands do
read live `/proc`, `/sys` and log files when you actually run the CLI, but those code paths
degrade gracefully when a file or tool isn't present (containers usually don't have
`lspci`/`lsusb`, for example).
