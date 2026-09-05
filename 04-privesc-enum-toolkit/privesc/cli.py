"""Entry point for privilege escalation enumeration checks."""

import argparse
import sys

from privesc import cron, sudo_perms, suid


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
