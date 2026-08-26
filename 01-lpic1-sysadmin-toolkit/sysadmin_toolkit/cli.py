"""Entry point tying the individual modules together into subcommands."""

import argparse
import sys

from sysadmin_toolkit import boot, filesystem, hardware, libraries, logs, packages, processes, textproc


def cmd_hardware(args):
    cpu = hardware.get_cpu_info()
    mem = hardware.get_memory_info()
    print(f"CPU: {cpu['model']} ({cpu['logical_cpus']} logical, "
          f"{cpu['physical_packages']} physical)")
    print(f"Memory: {mem['total_bytes'] // (1024 ** 2)} MB total, "
          f"{mem['available_bytes'] // (1024 ** 2)} MB available")
    print("\nPCI devices:")
    for dev in hardware.list_pci_devices()[:20]:
        print(f"  {dev}")
    print("\nUSB devices:")
    for dev in hardware.list_usb_devices()[:20]:
        print(f"  {dev}")
    print("\nBlock devices:")
    for dev in hardware.list_block_devices():
        print(f"  {dev['name']}: {dev['size_mb']} MB")


def cmd_packages(args):
    manager = packages.detect_package_manager()
    print(f"Package manager: {manager or 'not detected'}")
    installed = packages.list_installed_packages()
    print(f"Installed packages: {len(installed)}")
    split = packages.list_manual_vs_dependency()
    print(f"  manually installed: {len(split['manual'])}")
    print(f"  pulled in as dependency: {len(split['dependency'])}")


def cmd_boot(args):
    print(f"Firmware: {boot.detect_firmware()}")
    print(f"Init system: {boot.detect_init_system()}")
    target = boot.get_default_target()
    if target:
        print(f"Default target: {target}")
    print("\nfstab entries:")
    for entry in boot.parse_fstab():
        print(f"  {entry['device']} -> {entry['mount_point']} ({entry['fs_type']})")


def cmd_fs(args):
    print("Disk usage by FHS directory:")
    for path, usage in filesystem.disk_usage_by_fhs().items():
        used_mb = usage["used_bytes"] // (1024 ** 2)
        total_mb = usage["total_bytes"] // (1024 ** 2)
        print(f"  {path}: {used_mb}/{total_mb} MB")

    findings = filesystem.permission_audit()
    print("\nPermission audit:")
    if not findings:
        print("  no issues found")
    for finding in findings:
        print(f"  {finding['path']}: mode {finding['actual']} exceeds "
              f"expected max {finding['expected_max']}")

    broken = filesystem.find_broken_symlinks(args.symlink_root)
    print(f"\nBroken symlinks under {args.symlink_root}: {len(broken)}")
    for link in broken[:20]:
        print(f"  {link}")


def cmd_logs(args):
    parsed = logs.parse_auth_log(args.log_path)
    summary = logs.summarize(parsed)
    print(f"Failed logins: {summary['total_failed']}")
    print(f"Accepted logins: {summary['total_accepted']}")
    print("\nTop offending IPs:")
    for ip, count in summary["top_failed_ips"]:
        print(f"  {ip}: {count}")
    print("\nTop targeted usernames:")
    for user, count in summary["top_failed_users"]:
        print(f"  {user}: {count}")


def cmd_processes(args):
    procs = processes.list_processes()
    print(f"Total processes: {len(procs)}")

    zombies = processes.find_zombies()
    print(f"Zombie processes: {len(zombies)}")
    for z in zombies:
        print(f"  pid {z['pid']} ({z['comm']}), ppid {z['ppid']}")

    print(f"\nTop {args.top} by memory:")
    for proc in processes.top_memory_consumers(args.top):
        print(f"  pid {proc['pid']} {proc['comm']}: {proc['rss_kb']} kB")


def cmd_libs(args):
    deps = libraries.check_dependencies(args.binary)
    print(f"Dependencies for {args.binary}:")
    for dep in deps:
        status = "ok" if dep["resolved"] else "MISSING"
        print(f"  {dep['name']}: {status}")

    missing = [d for d in deps if not d["resolved"]]
    if missing:
        print(f"\n{len(missing)} unresolved dependencies")

    print("\nld.so.conf search paths:")
    for entry in libraries.get_search_paths():
        marker = "" if entry["exists"] else " (missing)"
        print(f"  {entry['path']}{marker}")


def cmd_words(args):
    for word, count in textproc.word_frequency(args.file, top_n=args.top):
        print(f"  {word}: {count}")


def cmd_all(args):
    for fn in (cmd_hardware, cmd_packages, cmd_boot, cmd_fs):
        print("=" * 40)
        fn(args)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sysadmin-toolkit",
        description="LPIC-1 101-500 aligned system inspection toolkit",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("hardware", help="CPU, memory, PCI/USB/block devices").set_defaults(func=cmd_hardware)
    sub.add_parser("packages", help="installed package inventory").set_defaults(func=cmd_packages)
    sub.add_parser("boot", help="firmware, init system, fstab").set_defaults(func=cmd_boot)

    fs_parser = sub.add_parser("fs", help="disk usage, permissions, broken symlinks")
    fs_parser.add_argument("--symlink-root", default="/etc", help="directory to scan for broken symlinks")
    fs_parser.set_defaults(func=cmd_fs)

    logs_parser = sub.add_parser("logs", help="auth log analysis")
    logs_parser.add_argument("--log-path", default="/var/log/auth.log")
    logs_parser.set_defaults(func=cmd_logs)

    proc_parser = sub.add_parser("processes", help="process listing, zombies, top memory users")
    proc_parser.add_argument("--top", type=int, default=10, help="how many top memory consumers to show")
    proc_parser.set_defaults(func=cmd_processes)

    libs_parser = sub.add_parser("libs", help="shared library dependency check")
    libs_parser.add_argument("--binary", default="/bin/ls", help="binary to check with ldd")
    libs_parser.set_defaults(func=cmd_libs)

    words_parser = sub.add_parser("words", help="word frequency count for a text file")
    words_parser.add_argument("--file", required=True)
    words_parser.add_argument("--top", type=int, default=10)
    words_parser.set_defaults(func=cmd_words)

    all_parser = sub.add_parser("all", help="run hardware, packages, boot and fs")
    all_parser.add_argument("--symlink-root", default="/etc")
    all_parser.set_defaults(func=cmd_all)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
