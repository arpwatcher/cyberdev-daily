"""Subnet math: masks, network/broadcast addresses, host ranges."""

from netcalc.ipaddr import int_to_ip, ip_to_int


def cidr_to_mask(prefix_len):
    if not 0 <= prefix_len <= 32:
        raise ValueError(f"prefix length out of range: {prefix_len}")
    mask_bits = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return int_to_ip(mask_bits)


def mask_to_cidr(mask_str):
    mask_int = ip_to_int(mask_str)
    binary = f"{mask_int:032b}"
    if "01" in binary:
        raise ValueError(f"not a contiguous subnet mask: {mask_str}")
    return binary.count("1")


def wildcard_mask(prefix_len):
    mask_int = ip_to_int(cidr_to_mask(prefix_len))
    return int_to_ip(mask_int ^ 0xFFFFFFFF)


def subnet_info(ip_str, prefix_len):
    """Return network address, broadcast, usable host range and counts for
    the subnet containing ip_str/prefix_len."""
    if not 0 <= prefix_len <= 32:
        raise ValueError(f"prefix length out of range: {prefix_len}")

    ip_int = ip_to_int(ip_str)
    mask_int = ip_to_int(cidr_to_mask(prefix_len))
    network_int = ip_int & mask_int
    host_bits = 32 - prefix_len
    broadcast_int = network_int | (0xFFFFFFFF >> prefix_len) if host_bits else network_int

    total_hosts = 2 ** host_bits
    usable_hosts = max(total_hosts - 2, 0) if host_bits >= 1 else 0

    info = {
        "network": int_to_ip(network_int),
        "broadcast": int_to_ip(broadcast_int),
        "prefix_len": prefix_len,
        "netmask": cidr_to_mask(prefix_len),
        "wildcard": wildcard_mask(prefix_len),
        "total_hosts": total_hosts,
        "usable_hosts": usable_hosts,
    }

    if usable_hosts > 0:
        info["first_host"] = int_to_ip(network_int + 1)
        info["last_host"] = int_to_ip(broadcast_int - 1)
    else:
        info["first_host"] = None
        info["last_host"] = None

    return info


def same_subnet(ip_a, ip_b, prefix_len):
    mask_int = ip_to_int(cidr_to_mask(prefix_len))
    return (ip_to_int(ip_a) & mask_int) == (ip_to_int(ip_b) & mask_int)


def hosts_to_prefix(host_count):
    """Smallest prefix length whose subnet has room for host_count usable hosts."""
    if host_count < 1:
        raise ValueError("host_count must be at least 1")
    needed_addresses = host_count + 2
    host_bits = 0
    while (2 ** host_bits) < needed_addresses:
        host_bits += 1
    prefix_len = 32 - host_bits
    if prefix_len < 0:
        raise ValueError(f"host_count too large for ipv4: {host_count}")
    return prefix_len
