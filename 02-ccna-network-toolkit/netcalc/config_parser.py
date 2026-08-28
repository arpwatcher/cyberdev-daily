"""Parses basic Cisco IOS style running-config text: hostname, interfaces
with their ip addresses, and vlan definitions. Handles the common subset,
not the whole IOS command surface.
"""


def parse_config(text):
    hostname = None
    interfaces = []
    vlans = []
    current_iface = None
    current_vlan = None

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue

        indented = raw_line[0] in (" ", "\t")
        line = raw_line.strip()

        if line == "!":
            current_iface = None
            current_vlan = None
            continue

        if not indented:
            current_iface = None
            current_vlan = None

            if line.startswith("hostname "):
                hostname = line.split(None, 1)[1]
            elif line.startswith("interface "):
                current_iface = {
                    "name": line.split(None, 1)[1],
                    "ip_address": None,
                    "netmask": None,
                    "description": None,
                    "shutdown": False,
                    "switchport_vlan": None,
                }
                interfaces.append(current_iface)
            elif line.startswith("vlan "):
                current_vlan = {"id": int(line.split(None, 1)[1]), "name": None}
                vlans.append(current_vlan)
            continue

        if current_iface is not None:
            if line.startswith("ip address "):
                parts = line.split()
                current_iface["ip_address"] = parts[2]
                current_iface["netmask"] = parts[3]
            elif line.startswith("description "):
                current_iface["description"] = line[len("description "):]
            elif line == "shutdown":
                current_iface["shutdown"] = True
            elif line == "no shutdown":
                current_iface["shutdown"] = False
            elif line.startswith("switchport access vlan "):
                current_iface["switchport_vlan"] = int(line.split()[-1])
        elif current_vlan is not None:
            if line.startswith("name "):
                current_vlan["name"] = line[len("name "):]

    return {"hostname": hostname, "interfaces": interfaces, "vlans": vlans}
