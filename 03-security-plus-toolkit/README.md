# security-plus-toolkit

Started while going through Security+ material. Two areas so far: credential strength
and PKI/certificate hygiene, both things that show up constantly in the exam objectives
and in actual security work.

- `passwords.py` - entropy-based password strength scoring, a common-password blocklist
  check, and hash format identification from shape alone (length, bcrypt's `$2b$` prefix
  and so on - note md5/ntlm/md4 all produce 32 hex chars and can't be told apart without
  more context, so it says so rather than guessing)
- `tls.py` - X.509 certificate auditing using the `cryptography` library: expiry
  (including a warning window before actual expiry), weak key size (RSA under 2048 bits,
  EC under 256), weak/deprecated signature algorithms, self-signed detection

`tests/fixtures/*.pem` are real self-signed certs generated with
`tests/fixtures/make_test_certs.py` - one valid, one expired, one with a weak 1024-bit
key, one expiring soon. Modern `cryptography` refuses to sign a cert with md5 or sha1
(tried it, it just raises), so the weak-signature check is unit tested directly against
its input dict instead of a generated fixture.

## Usage

```
cd 03-security-plus-toolkit
python -m secplus.cli check-password --password 'correct-horse-battery-staple'
python -m secplus.cli identify-hash 5f4dcc3b5aa765d61d8327deb882cf99
python -m secplus.cli check-cert tests/fixtures/expired.pem
```

## Tests

```
pip install cryptography pytest
pytest
```

20 tests. The cert tests run against the real generated pem fixtures, not mocked data,
so they're actually parsing x509 structures the same way the cli does.
