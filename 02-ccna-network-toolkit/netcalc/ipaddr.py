"""IPv4 address parsing and classification, done with plain integer math
instead of the stdlib ipaddress module - the point is understanding the bits.
"""

PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
]


def validate_ip(ip_str):
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
        if len(part) > 1 and part[0] == "0":
            return False
    return True


def ip_to_int(ip_str):
    if not validate_ip(ip_str):
        raise ValueError(f"invalid ipv4 address: {ip_str}")
    octets = [int(p) for p in ip_str.split(".")]
    value = 0
    for octet in octets:
        value = (value << 8) | octet
    return value


def int_to_ip(value):
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"value out of ipv4 range: {value}")
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def classify(ip_str):
    first_octet = int(ip_str.split(".")[0])
    if first_octet < 128:
        return "A"
    if first_octet < 192:
        return "B"
    if first_octet < 224:
        return "C"
    if first_octet < 240:
        return "D"
    return "E"


def is_private(ip_str):
    value = ip_to_int(ip_str)
    for start, end in PRIVATE_RANGES:
        if ip_to_int(start) <= value <= ip_to_int(end):
            return True
    return False
