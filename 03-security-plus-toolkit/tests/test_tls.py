from pathlib import Path

from secplus import tls

FIXTURES = Path(__file__).parent / "fixtures"


def test_valid_strong_cert_no_expiry_or_key_findings():
    cert = tls.load_certificate(FIXTURES / "valid_strong.pem")
    result = tls.audit_certificate(cert)
    assert result["info"]["key_type"] == "rsa"
    assert result["info"]["key_size"] == 2048
    assert not result["info"]["is_expired"]
    assert not any("weak" in f for f in result["findings"])


def test_expired_cert_flagged():
    cert = tls.load_certificate(FIXTURES / "expired.pem")
    result = tls.audit_certificate(cert)
    assert result["info"]["is_expired"]
    assert any("expired" in f for f in result["findings"])


def test_weak_key_cert_flagged():
    cert = tls.load_certificate(FIXTURES / "weak_key.pem")
    result = tls.audit_certificate(cert)
    assert result["info"]["key_size"] == 1024
    assert any("weak key" in f for f in result["findings"])


def test_expiring_soon_cert_flagged_but_not_expired():
    cert = tls.load_certificate(FIXTURES / "expiring_soon.pem")
    result = tls.audit_certificate(cert)
    assert not result["info"]["is_expired"]
    assert any("expiring in" in f for f in result["findings"])


def test_self_signed_detected():
    cert = tls.load_certificate(FIXTURES / "valid_strong.pem")
    info = tls.inspect_certificate(cert)
    assert info["is_self_signed"]


def test_check_weak_signature_flags_sha1_and_md5():
    assert tls.check_weak_signature({"signature_algorithm": "sha1"})
    assert tls.check_weak_signature({"signature_algorithm": "md5"})
    assert not tls.check_weak_signature({"signature_algorithm": "sha256"})


def test_check_weak_key_rsa_threshold():
    assert tls.check_weak_key({"key_type": "rsa", "key_size": 1024})
    assert not tls.check_weak_key({"key_type": "rsa", "key_size": 2048})


def test_check_weak_key_ec_threshold():
    assert tls.check_weak_key({"key_type": "ec", "key_size": 160})
    assert not tls.check_weak_key({"key_type": "ec", "key_size": 256})


def test_check_weak_key_unknown_type_not_flagged():
    assert not tls.check_weak_key({"key_type": "unknown", "key_size": None})
