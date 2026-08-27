"""Entry point for subnet/vlsm calculations."""

import argparse
import sys

from netcalc import ipaddr, subnetting, vlsm


def cmd_info(args):
    info = subnetting.subnet_info(args.ip, args.prefix)
    print(f"{args.ip}/{args.prefix}")
    print(f"  network:    {info['network']}")
    print(f"  broadcast:  {info['broadcast']}")
    print(f"  netmask:    {info['netmask']}")
    print(f"  wildcard:   {info['wildcard']}")
    print(f"  hosts:      {info['usable_hosts']} usable ({info['total_hosts']} total)")
    if info["first_host"]:
        print(f"  host range: {info['first_host']} - {info['last_host']}")
    print(f"  class:      {ipaddr.classify(args.ip)}")
    print(f"  private:    {ipaddr.is_private(args.ip)}")


def cmd_vlsm(args):
    requirements = []
    for item in args.hosts:
        name, _, count = item.partition(":")
        if not count:
            print(f"error: expected name:hosts, got '{item}'", file=sys.stderr)
            return 1
        requirements.append((name, int(count)))

    try:
        allocations = vlsm.allocate(args.network, args.prefix, requirements)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"VLSM allocation for {args.network}/{args.prefix}:")
    for alloc in allocations:
        print(f"  {alloc['name']:<15} {alloc['network']}/{alloc['prefix_len']:<3} "
              f"usable {alloc['usable_hosts']:>5} (needed {alloc['requested_hosts']})")
    print(f"\naddress space utilization: {vlsm.utilization(allocations):.0%}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netcalc", description="subnet and vlsm calculator for ccna study",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    info_parser = sub.add_parser("info", help="subnet info for an ip/prefix")
    info_parser.add_argument("ip")
    info_parser.add_argument("prefix", type=int)
    info_parser.set_defaults(func=cmd_info)

    vlsm_parser = sub.add_parser("vlsm", help="allocate a base network across host requirements")
    vlsm_parser.add_argument("network")
    vlsm_parser.add_argument("prefix", type=int)
    vlsm_parser.add_argument("hosts", nargs="+", help="name:host_count pairs, e.g. sales:50")
    vlsm_parser.set_defaults(func=cmd_vlsm)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
