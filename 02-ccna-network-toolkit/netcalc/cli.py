"""Entry point for subnet/vlsm calculations."""

import argparse
import sys

from netcalc import config_parser, ipaddr, subnetting, topology, vlsm


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


def cmd_parse_config(args):
    config = config_parser.parse_config(open(args.config).read())
    print(f"hostname: {config['hostname'] or '(none)'}")
    print("\ninterfaces:")
    for iface in config["interfaces"]:
        status = "shutdown" if iface["shutdown"] else "up"
        ip_part = f"{iface['ip_address']} {iface['netmask']}" if iface["ip_address"] else "no ip"
        print(f"  {iface['name']}: {ip_part} ({status})")
    if config["vlans"]:
        print("\nvlans:")
        for vlan in config["vlans"]:
            print(f"  {vlan['id']}: {vlan['name'] or '(unnamed)'}")


def cmd_conflicts(args):
    devices = topology.load_devices_from_dir(args.config_dir)
    conflicts = topology.find_ip_conflicts(devices)
    if not conflicts:
        print("no ip conflicts found")
        return
    for c in conflicts:
        where = ", ".join(f"{a['device']}:{a['interface']}" for a in c["assignments"])
        print(f"  {c['ip_address']} assigned on: {where}")


def cmd_overlaps(args):
    devices = topology.load_devices_from_dir(args.config_dir)
    overlaps = topology.find_subnet_overlaps(devices)
    if not overlaps:
        print("no subnet overlaps found")
        return
    for o in overlaps:
        a, b = o["a"], o["b"]
        print(f"  {a['device']} {a['network']}/{a['prefix_len']} overlaps "
              f"{b['device']} {b['network']}/{b['prefix_len']}")


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

    config_parser_cmd = sub.add_parser("parse-config", help="parse a cisco-style config file")
    config_parser_cmd.add_argument("config")
    config_parser_cmd.set_defaults(func=cmd_parse_config)

    conflicts_parser = sub.add_parser("conflicts", help="find duplicate ips across a directory of configs")
    conflicts_parser.add_argument("config_dir")
    conflicts_parser.set_defaults(func=cmd_conflicts)

    overlaps_parser = sub.add_parser("overlaps", help="find overlapping subnets across a directory of configs")
    overlaps_parser.add_argument("config_dir")
    overlaps_parser.set_defaults(func=cmd_overlaps)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
