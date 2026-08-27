"""Variable Length Subnet Masking: carve a base network into right-sized
subnets for a list of host requirements, biggest first, no wasted space.
"""

from netcalc import subnetting
from netcalc.ipaddr import int_to_ip, ip_to_int


def allocate(base_network, base_prefix, requirements):
    """requirements is a list of (name, host_count) pairs.

    Returns a list of dicts (network, prefix_len, name, plus everything
    subnetting.subnet_info gives you), sorted largest block first - that's
    the standard way VLSM allocation tables are laid out, and it's also
    what makes the sequential packing work without gaps.
    """
    if not requirements:
        raise ValueError("no host requirements given")

    base_info = subnetting.subnet_info(base_network, base_prefix)
    base_network_int = ip_to_int(base_info["network"])
    base_broadcast_int = ip_to_int(base_info["broadcast"])

    ordered = sorted(requirements, key=lambda r: r[1], reverse=True)

    allocations = []
    current = base_network_int
    for name, host_count in ordered:
        prefix_len = subnetting.hosts_to_prefix(host_count)
        block_size = 2 ** (32 - prefix_len)

        if current % block_size != 0:
            current = ((current // block_size) + 1) * block_size

        block_end = current + block_size - 1
        if block_end > base_broadcast_int:
            raise ValueError(
                f"'{name}' needing {host_count} hosts doesn't fit in "
                f"{base_network}/{base_prefix} - out of address space"
            )

        info = subnetting.subnet_info(int_to_ip(current), prefix_len)
        info["name"] = name
        info["requested_hosts"] = host_count
        allocations.append(info)

        current += block_size

    return allocations


def utilization(allocations):
    """Fraction of allocated address space actually used by requested hosts."""
    total_addresses = sum(a["total_hosts"] for a in allocations)
    total_requested = sum(a["requested_hosts"] for a in allocations)
    if total_addresses == 0:
        return 0.0
    return total_requested / total_addresses
