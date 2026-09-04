# security-plus-toolkit

Started while going through Security+ material. Credential strength, PKI/certificate
hygiene, firewall rule review, and basic malware hash lookup - things that show up
constantly in the exam objectives and in actual security work.

- `passwords.py` - entropy-based password strength scoring, a common-password blocklist
  check, and hash format identification from shape alone (length, bcrypt's `$2b$` prefix
  and so on - note md5/ntlm/md4 all produce 32 hex chars and can't be told apart without
  more context, so it says so rather than guessing)
- `tls.py` - X.509 certificate auditing using the `cryptography` library: expiry
  (including a warning window before actual expiry), weak key size (RSA under 2048 bits,
  EC under 256), weak/deprecated signature algorithms, self-signed detection
- `firewall.py` - parses iptables-save style output and flags common misconfigurations:
  permissive default policies (INPUT/FORWARD set to ACCEPT), sensitive ports (ssh, rdp,
  database ports) open to any source instead of a restricted subnet, cleartext protocols
  allowed through at all
- `ioc.py` - hashes files (sha256 by default, others supported) and checks them against
  a local list of known-bad hashes - the basic move behind any "is this file malware"
  check before you get into sandboxing or behavioral analysis

`tests/fixtures/*.pem` are real self-signed certs generated with
`tests/fixtures/make_test_certs.py` - one valid, one expired, one with a weak 1024-bit
key, one expiring soon. Modern `cryptography` refuses to sign a cert with md5 or sha1
(tried it, it just raises), so the weak-signature check is unit tested directly against
its input dict instead of a generated fixture. `tests/fixtures/ioc_samples/` has a real
"malicious" file whose actual sha256 is in `sample_iocs.txt`, generated with
`make_ioc_fixtures.py`, so the scan is checked against a real computed hash, not a
hardcoded one.

## Usage

```
cd 03-security-plus-toolkit
python -m secplus.cli check-password --password 'correct-horse-battery-staple'
python -m secplus.cli identify-hash 5f4dcc3b5aa765d61d8327deb882cf99
python -m secplus.cli check-cert tests/fixtures/expired.pem
python -m secplus.cli check-firewall tests/fixtures/sample_iptables.rules
python -m secplus.cli scan-iocs tests/fixtures/ioc_samples tests/fixtures/sample_iocs.txt
```

## Tests

```
pip install cryptography pytest
pytest
```

39 tests. The cert tests run against real generated pem fixtures, not mocked data, and
the ioc tests hash a real file and check it against a real list, so both are exercising
the actual code paths the cli uses, not just the parsing logic in isolation.
