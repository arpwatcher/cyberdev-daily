"""X.509 certificate inspection. Security+ domain 2 (architecture) covers
PKI heavily - this checks the things that actually go wrong in practice:
expired certs, weak keys, weak signature algorithms, self-signed certs
where you wouldn't expect one.
"""

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

WEAK_SIGNATURE_ALGORITHMS = {"md5", "sha1"}
MIN_RSA_KEY_SIZE = 2048
MIN_EC_KEY_SIZE = 256


def load_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _key_info(cert):
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ec", public_key.curve.key_size
    return "unknown", None


def _as_utc(dt):
    # older cryptography versions return naive datetimes that are UTC in
    # substance but carry no tzinfo, so comparisons against an aware "now"
    # blow up unless we attach it ourselves
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def inspect_certificate(cert):
    now = datetime.now(timezone.utc)
    not_after = _as_utc(cert.not_valid_after)
    not_before = _as_utc(cert.not_valid_before)
    key_type, key_size = _key_info(cert)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "is_self_signed": cert.subject == cert.issuer,
        "not_valid_before": not_before,
        "not_valid_after": not_after,
        "is_expired": now > not_after,
        "days_until_expiry": (not_after - now).days,
        "key_type": key_type,
        "key_size": key_size,
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
    }


def check_weak_signature(cert_info):
    return cert_info["signature_algorithm"] in WEAK_SIGNATURE_ALGORITHMS


def check_weak_key(cert_info):
    if cert_info["key_type"] == "rsa":
        return cert_info["key_size"] < MIN_RSA_KEY_SIZE
    if cert_info["key_type"] == "ec":
        return cert_info["key_size"] < MIN_EC_KEY_SIZE
    return False


def audit_certificate(cert):
    """Run all the checks and return one findings dict for a certificate."""
    info = inspect_certificate(cert)
    findings = []

    if info["is_expired"]:
        findings.append(f"expired {abs(info['days_until_expiry'])} days ago")
    elif info["days_until_expiry"] < 30:
        findings.append(f"expiring in {info['days_until_expiry']} days")

    if check_weak_signature(info):
        findings.append(f"weak signature algorithm: {info['signature_algorithm']}")

    if check_weak_key(info):
        findings.append(f"weak key: {info['key_type']} {info['key_size']} bits")

    if info["is_self_signed"]:
        findings.append("self-signed")

    return {"info": info, "findings": findings}
