# ccna-network-toolkit

Subnet and VLSM calculator built while going through CCNA material. Bigger in scope than
the LPIC-1 toolkit on purpose - this one does real subnetting math from scratch instead of
just wrapping Python's ipaddress module, since the point was actually learning the bit math.

- `ipaddr.py` - IPv4 parsing/validation, classful classification (A-E), RFC1918 private
  range checks, all done with plain integer arithmetic
- `subnetting.py` - CIDR/mask conversion, network and broadcast address calculation,
  usable host ranges, wildcard masks, same-subnet checks
- `vlsm.py` - variable length subnet mask allocation: given a base network and a list of
  host requirements, carves out right-sized subnets biggest first with no gaps or overlap
- `config_parser.py` - parses basic Cisco IOS style running-config text: hostname,
  interfaces (ip, mask, description, shutdown state), vlan definitions
- `topology.py` - loads a directory of device configs and cross-checks them: duplicate
  IP addresses assigned on different devices, and subnets that overlap when they shouldn't
  (as opposed to two interfaces correctly sharing one LAN subnet)

## Usage

```
cd 02-ccna-network-toolkit
python -m netcalc.cli info 192.168.1.100 26
python -m netcalc.cli vlsm 192.168.1.0 24 sales:50 engineering:20 management:10 link:2
python -m netcalc.cli parse-config tests/fixtures/router1.cfg
python -m netcalc.cli conflicts tests/fixtures
python -m netcalc.cli overlaps tests/fixtures
```

## Tests

```
pip install pytest
pytest
```

Subnet/VLSM tests are pure math against known values. The VLSM allocation is checked
against the standard textbook example (192.168.1.0/24 split for 50/20/10/2 hosts) and
against overlap/gap invariants directly. Config parsing and topology checks run against
fixture Cisco configs in `tests/fixtures/` (router1-3.cfg), including a deliberate
duplicate IP and a deliberately nested subnet so the detection logic has something real
to catch.
