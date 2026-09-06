"""Entry point for privilege escalation enumeration checks."""

import argparse
import os
import sys

from privesc import capabilities, cron, path_check, sudo_perms, suid


def cmd_suid(args):
    findings = suid.find_suid_sgid(args.root)
    print(f"{len(findings)} suid/sgid files found")

    unexpected = suid.flag_unexpected(findings)
    if unexpected:
        print("\nunexpected (not in the common baseline):")
        for f in unexpected:
            bits = "+".join(b for b, v in [("suid", f["suid"]), ("sgid", f["sgid"])] if v)
            print(f"  {f['path']} ({bits})")
    else:
        print("\nnothing outside the common baseline")


def cmd_sudo(args):
    result = sudo_perms.audit(open(args.sudo_l).read())
    print(f"{len(result['entries'])} sudo entries")

    if result["blanket_all"]:
        print("\nblanket ALL permissions:")
        for e in result["blanket_all"]:
            print(f"  ({e['runas']}) ALL")

    if result["dangerous_binaries"]:
        print("\ngtfobins-style dangerous binaries allowed via sudo:")
        for e in result["dangerous_binaries"]:
            tag = "NOPASSWD " if e["nopasswd"] else ""
            print(f"  ({e['runas']}) {tag}{e['command']}")

    if not result["blanket_all"] and not result["dangerous_binaries"]:
        print("\nno obvious sudo escalation paths found")


def cmd_cron(args):
    parser_fn = cron.parse_user_crontab if args.user_format else cron.parse_system_crontab
    jobs = parser_fn(open(args.crontab).read())
    print(f"{len(jobs)} cron jobs found")

    findings = cron.find_writable_targets(jobs)
    if findings:
        print("\nwritable script targets:")
        for f in findings:
            print(f"  {f['script_path']} ({f['reason']}, runs as {f['user'] or 'current user'})")
    else:
        print("\nno writable cron targets found")


def cmd_path(args):
    path_str = args.path or os.environ.get("PATH", "")
    dirs = path_check.parse_path(path_str)
    binaries = args.binaries.split(",") if args.binaries else ["sudo", "python3", "bash", "ls"]

    writable = path_check.find_writable_dirs(dirs)
    print(f"{len(dirs)} directories in PATH, {len(writable)} writable")
    for d in writable:
        print(f"  writable: {d}")

    findings = path_check.find_hijackable_binaries(dirs, binaries)
    if findings:
        print("\nhijackable binaries:")
        for f in findings:
            print(f"  {f['binary']} could be shadowed from {f['writable_dir']}")
    else:
        print("\nno hijackable binaries found among checked names")


def cmd_caps(args):
    entries = capabilities.parse_getcap_output(open(args.getcap_output).read())
    print(f"{len(entries)} binaries with capabilities")

    findings = capabilities.flag_dangerous(entries)
    if findings:
        print("\ndangerous capabilities found:")
        for f in findings:
            print(f"  {f['path']}: {', '.join(f['dangerous_caps'])}")
    else:
        print("\nno dangerous capabilities found")


def build_parser():
    parser = argparse.ArgumentParser(prog="privesc", description="linux privesc enumeration toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    suid_parser = sub.add_parser("suid", help="scan for suid/sgid binaries")
    suid_parser.add_argument("root", help="directory to scan")
    suid_parser.set_defaults(func=cmd_suid)

    sudo_parser = sub.add_parser("sudo", help="audit sudo -l output")
    sudo_parser.add_argument("sudo_l", help="path to a file containing sudo -l output")
    sudo_parser.set_defaults(func=cmd_sudo)

    cron_parser = sub.add_parser("cron", help="check cron jobs for writable targets")
    cron_parser.add_argument("crontab", help="path to a crontab file")
    cron_parser.add_argument("--user-format", action="store_true",
                              help="parse as a user crontab (no user field) instead of /etc/crontab style")
    cron_parser.set_defaults(func=cmd_cron)

    path_parser = sub.add_parser("path", help="check PATH for directory-order hijacking")
    path_parser.add_argument("--path", help="PATH string to check, defaults to the current environment's")
    path_parser.add_argument("--binaries", help="comma separated binary names to check")
    path_parser.set_defaults(func=cmd_path)

    caps_parser = sub.add_parser("caps", help="audit getcap -r / output for dangerous capabilities")
    caps_parser.add_argument("getcap_output", help="path to a file containing getcap -r / output")
    caps_parser.set_defaults(func=cmd_caps)

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
