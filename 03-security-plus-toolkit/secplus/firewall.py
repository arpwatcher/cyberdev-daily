"""Parses iptables-save style output and flags common misconfigurations.
Security+ domain 3 (implementation) - firewall rule review shows up constantly
in both the exam and actual hardening work.
"""

import re

RULE_RE = re.compile(r"-A\s+(?P<chain>\S+)(?P<rest>.*)")

SENSITIVE_PORTS = {
    22: "ssh",
    23: "telnet",
    3389: "rdp",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
}

CLEARTEXT_PORTS = {21: "ftp", 23: "telnet", 80: "http", 25: "smtp", 110: "pop3", 143: "imap"}

ANY_SOURCE = {None, "0.0.0.0/0", "::/0"}


def parse_config(text):
    """Returns {"policies": {chain: default_target}, "rules": [rule dicts]}."""
    policies = {}
    rules = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("*") or line == "COMMIT":
            continue

        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2:
                policies[parts[0]] = parts[1]
            continue

        match = RULE_RE.match(line)
        if not match:
            continue

        rule = {"chain": match.group("chain"), "proto": None, "src": None,
                 "dst": None, "dport": None, "sport": None, "jump": None}
        tokens = match.group("rest").split()

        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == "-p" and i + 1 < len(tokens):
                rule["proto"] = tokens[i + 1]
                i += 2
            elif token == "-s" and i + 1 < len(tokens):
                rule["src"] = tokens[i + 1]
                i += 2
            elif token == "-d" and i + 1 < len(tokens):
                rule["dst"] = tokens[i + 1]
                i += 2
            elif token == "--dport" and i + 1 < len(tokens):
                rule["dport"] = int(tokens[i + 1])
                i += 2
            elif token == "--sport" and i + 1 < len(tokens):
                rule["sport"] = int(tokens[i + 1])
                i += 2
            elif token == "-j" and i + 1 < len(tokens):
                rule["jump"] = tokens[i + 1]
                i += 2
            else:
                i += 1

        rules.append(rule)

    return {"policies": policies, "rules": rules}


def find_permissive_default_policies(config):
    """Default ACCEPT on INPUT/FORWARD means anything not explicitly
    blocked gets through - the opposite of how a firewall should default."""
    findings = []
    for chain in ("INPUT", "FORWARD"):
        policy = config["policies"].get(chain)
        if policy == "ACCEPT":
            findings.append({"chain": chain, "policy": policy})
    return findings


def find_exposed_sensitive_ports(config):
    """ACCEPT rules on sensitive ports with no source restriction - open to
    the whole internet, not just an admin subnet."""
    findings = []
    for rule in config["rules"]:
        if rule["jump"] != "ACCEPT" or rule["dport"] is None:
            continue
        if rule["dport"] not in SENSITIVE_PORTS:
            continue
        if rule["src"] in ANY_SOURCE:
            findings.append({
                "chain": rule["chain"],
                "port": rule["dport"],
                "service": SENSITIVE_PORTS[rule["dport"]],
            })
    return findings


def find_cleartext_services(config):
    findings = []
    for rule in config["rules"]:
        if rule["jump"] != "ACCEPT" or rule["dport"] is None:
            continue
        if rule["dport"] in CLEARTEXT_PORTS:
            findings.append({
                "chain": rule["chain"],
                "port": rule["dport"],
                "service": CLEARTEXT_PORTS[rule["dport"]],
            })
    return findings


def audit(config):
    return {
        "permissive_defaults": find_permissive_default_policies(config),
        "exposed_sensitive_ports": find_exposed_sensitive_ports(config),
        "cleartext_services": find_cleartext_services(config),
    }
