"""Auto-detects the most likely encoding of the input string."""
import re
import string

def detect(text: str) -> list[str]:
    """Return list of human-readable hints about what the input might be."""
    hints = []
    t = text.strip()

    # Base64 hints
    b64_chars = set(string.ascii_letters + string.digits + '+/=')
    if len(t) % 4 == 0 and all(c in b64_chars for c in t) and len(t) >= 4:
        hints.append("possible Base64 (length divisible by 4, valid charset)")

    # Hex
    if re.fullmatch(r'[0-9a-fA-F\s]+', t) and len(t.replace(' ', '')) % 2 == 0:
        hints.append("possible Hex string")

    # Binary
    if re.fullmatch(r'[01\s]+', t) and len(t.replace(' ', '')) % 8 == 0:
        hints.append("possible Binary (8-bit chunks)")

    # Morse code
    if re.fullmatch(r'[.\-/ ]+', t):
        hints.append("possible Morse code")

    # Hash patterns
    clean = t.replace(' ', '')
    if re.fullmatch(r'[0-9a-fA-F]{32}', clean):
        hints.append("looks like MD5 hash (32 hex chars)")
    if re.fullmatch(r'[0-9a-fA-F]{40}', clean):
        hints.append("looks like SHA1 hash (40 hex chars)")
    if re.fullmatch(r'[0-9a-fA-F]{64}', clean):
        hints.append("looks like SHA256 hash (64 hex chars)")

    # URL encoded
    if '%' in t and re.search(r'%[0-9a-fA-F]{2}', t):
        hints.append("possible URL encoding (%XX)")

    # Pure digits
    if t.replace(' ', '').isdigit():
        hints.append("pure numeric input (decimal/ASCII codes?)")

    # Base32
    b32_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
    if all(c in b32_chars for c in t.upper()) and len(t) % 8 == 0:
        hints.append("possible Base32")

    return hints
