from secplus import passwords


def test_common_password_flagged_very_weak():
    result = passwords.score_password("password")
    assert result["strength"] == "very weak"
    assert result["reason"] == "common password"


def test_common_password_case_insensitive():
    result = passwords.score_password("PaSSwoRd")
    assert result["reason"] == "common password"


def test_short_password_is_weak():
    result = passwords.score_password("ab1")
    assert result["strength"] in ("very weak", "weak")


def test_long_mixed_password_is_strong():
    result = passwords.score_password("Xk9$mQ2#vL8pR4nT7w")
    assert result["strength"] in ("strong", "very strong")


def test_entropy_increases_with_charset():
    lower_only = passwords.entropy_bits("abcdefgh")
    mixed = passwords.entropy_bits("aB3$efgh")
    assert mixed > lower_only


def test_entropy_zero_for_empty():
    assert passwords.entropy_bits("") == 0.0


def test_charset_size_all_categories():
    assert passwords.charset_size("aB3$") == 26 + 26 + 10 + 33


def test_identify_hash_md5_length():
    assert passwords.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99") == "md5-or-ntlm-or-md4"


def test_identify_hash_sha256_length():
    value = "a" * 64
    assert passwords.identify_hash(value) == "sha256"


def test_identify_hash_bcrypt():
    value = "$2b$12$" + "a" * 53
    assert passwords.identify_hash(value) == "bcrypt"


def test_identify_hash_unknown():
    assert passwords.identify_hash("not a hash") == "unknown"
