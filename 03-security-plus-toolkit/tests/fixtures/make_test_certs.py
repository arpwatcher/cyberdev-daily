"""Builds the test certificate fixtures. Not part of the test suite - run
manually if they ever need regenerating:
    python tests/fixtures/make_test_certs.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

FIXTURES_DIR = Path(__file__).parent


def make_self_signed_cert(key_size, not_before_days_ago, not_after_days_from_now, name="test.example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=not_before_days_ago))
        .not_valid_after(now + datetime.timedelta(days=not_after_days_from_now))
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert


def write_pem(cert, path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


valid_strong = make_self_signed_cert(key_size=2048, not_before_days_ago=1, not_after_days_from_now=365)
write_pem(valid_strong, FIXTURES_DIR / "valid_strong.pem")

expired = make_self_signed_cert(key_size=2048, not_before_days_ago=60, not_after_days_from_now=-30)
write_pem(expired, FIXTURES_DIR / "expired.pem")

weak_key = make_self_signed_cert(key_size=1024, not_before_days_ago=1, not_after_days_from_now=365)
write_pem(weak_key, FIXTURES_DIR / "weak_key.pem")

expiring_soon = make_self_signed_cert(key_size=2048, not_before_days_ago=1, not_after_days_from_now=10)
write_pem(expiring_soon, FIXTURES_DIR / "expiring_soon.pem")

print("wrote valid_strong.pem, expired.pem, weak_key.pem, expiring_soon.pem")
