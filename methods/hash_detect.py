"""Hash detection: identifies likely hash types by length and charset. No cracking."""
import re

def _hex_len(text: str, length: int) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]+', text.strip())) and len(text.strip()) == length

def identify_md5(text: str):
    t = text.strip()
    if _hex_len(t, 32):
        return f"[HASH DETECTED] Looks like MD5 (32 hex chars): {t}"
    return None

def identify_sha1(text: str):
    t = text.strip()
    if _hex_len(t, 40):
        return f"[HASH DETECTED] Looks like SHA1 (40 hex chars): {t}"
    return None

def identify_sha256(text: str):
    t = text.strip()
    if _hex_len(t, 64):
        return f"[HASH DETECTED] Looks like SHA256 (64 hex chars): {t}"
    return None

def identify_sha512(text: str):
    t = text.strip()
    if _hex_len(t, 128):
        return f"[HASH DETECTED] Looks like SHA512 (128 hex chars): {t}"
    return None

def identify_other_hashes(text: str):
    t = text.strip()
    if t.startswith('$2') and len(t) == 60:
        return f"[HASH DETECTED] Looks like bcrypt: {t}"
    if re.fullmatch(r'[0-9a-fA-F]{32}', t):
        return f"[HASH DETECTED] Looks like NTLM (32 hex chars): {t}"
    if t.startswith('{') and t.endswith('}'):
        return f"[HASH DETECTED] Looks like LDAP-style hash: {t}"
    return None

def get_methods():
    return [
        ("Hash Identify: MD5",    identify_md5),
        ("Hash Identify: SHA1",   identify_sha1),
        ("Hash Identify: SHA256", identify_sha256),
        ("Hash Identify: SHA512", identify_sha512),
        ("Hash Identify: Other",  identify_other_hashes),
    ]
