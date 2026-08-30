"""Password strength scoring and hash format identification. Security+
domain 1 (threats) and domain 4 (identity and access management) both touch
on this - weak credentials and how to recognize what you're looking at when
you find a hash dump.
"""

import math
import re

BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")
HEX_RE = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)

# hex-only hashes are identified purely by length, since md5/ntlm/md4 all
# produce 32 hex chars and can't be told apart without more context
HEX_LENGTH_TO_NAME = {32: "md5-or-ntlm-or-md4", 40: "sha1", 64: "sha256", 128: "sha512"}

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "letmein", "admin",
    "welcome", "monkey", "dragon", "football", "iloveyou", "changeme",
}


def charset_size(password):
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33
    return size


def entropy_bits(password):
    """Rough shannon-style entropy estimate: length * log2(charset size).
    Not a substitute for a real cracking-time model, but good enough to
    rank passwords against each other."""
    if not password:
        return 0.0
    charset = charset_size(password)
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


def score_password(password):
    if password.lower() in COMMON_PASSWORDS:
        return {"entropy_bits": 0.0, "strength": "very weak", "reason": "common password"}

    bits = entropy_bits(password)
    if bits < 28:
        strength = "very weak"
    elif bits < 36:
        strength = "weak"
    elif bits < 60:
        strength = "reasonable"
    elif bits < 80:
        strength = "strong"
    else:
        strength = "very strong"

    return {"entropy_bits": round(bits, 1), "strength": strength, "reason": None}


def identify_hash(value):
    """Guess the hash format from shape alone. md5/ntlm/md4 are all 32 hex
    chars so this can't disambiguate those without more context - it says so."""
    value = value.strip()

    if BCRYPT_RE.match(value):
        return "bcrypt"

    if HEX_RE.match(value):
        return HEX_LENGTH_TO_NAME.get(len(value), "unknown")

    return "unknown"
