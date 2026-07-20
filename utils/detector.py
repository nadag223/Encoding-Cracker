"""Auto-detects the most likely encoding of the input string with structural fingerprinting."""
import re
import string
import base64

def detect(text: str) -> list[str]:
    """Return list of human-readable hints about what the input might be."""
    hints = []
    t = text.strip()
    clean = t.replace(' ', '')

    # Base64 hints
    b64_chars = set(string.ascii_letters + string.digits + '+/=')
    if len(t) % 4 == 0 and all(c in b64_chars for c in t) and len(t) >= 4:
        hints.append("possible Base64 (length divisible by 4, valid charset)")

    # Base64 URL-safe
    b64url_chars = set(string.ascii_letters + string.digits + '-_')
    if len(t) % 4 == 0 and all(c in b64url_chars for c in t) and len(t) >= 4:
        hints.append("possible Base64 URL-safe (no padding)")

    # Hex
    if re.fullmatch(r'[0-9a-fA-F\s]+', t) and len(clean) % 2 == 0:
        hints.append("possible Hex string")

    # Binary
    if re.fullmatch(r'[01\s]+', t) and len(clean) % 8 == 0:
        hints.append("possible Binary (8-bit chunks)")

    # Morse code
    if re.fullmatch(r'[.\-/ \s]+', t):
        hints.append("possible Morse code")

    # Hash patterns
    if re.fullmatch(r'[0-9a-fA-F]{32}', clean):
        hints.append("looks like MD5 hash (32 hex chars)")
    if re.fullmatch(r'[0-9a-fA-F]{40}', clean):
        hints.append("looks like SHA1 hash (40 hex chars)")
    if re.fullmatch(r'[0-9a-fA-F]{64}', clean):
        hints.append("looks like SHA256 hash (64 hex chars)")
    if re.fullmatch(r'[0-9a-fA-F]{128}', clean):
        hints.append("looks like SHA512 hash (128 hex chars)")

    # URL encoded
    if '%' in t and re.search(r'%[0-9a-fA-F]{2}', t):
        hints.append("possible URL encoding (%XX)")

    # Pure digits
    if clean.isdigit():
        hints.append("pure numeric input (decimal/ASCII codes?)")

    # Base32
    b32_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
    if all(c in b32_chars for c in t.upper()) and len(t) % 8 == 0:
        hints.append("possible Base32")

    # Base36
    b36_chars = set('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    if all(c in b36_chars for c in clean.upper()) and len(clean) > 0:
        hints.append("possible Base36")

    # Base58
    b58_chars = set('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
    if all(c in b58_chars for c in clean) and len(clean) > 0:
        hints.append("possible Base58 (Bitcoin-style)")

    # Base85
    b85_chars = set(string.printable) - set(['\n', '\r'])
    if all(c in b85_chars for c in clean) and len(clean) > 0 and len(clean) % 5 == 0:
        hints.append("possible Base85 (RFC1924/Ascii85)")

    # --- Structural Fingerprinting ---

    # JWT (JSON Web Token)
    if re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', t):
        hints.append("JWT structure (header.payload.signature)")

    # PEM format
    if t.startswith('-----BEGIN ') and t.endswith('-----'):
        hints.append("PEM/DER format (certificate/key)")

    # Zlib/Gzip/Bzip2 magic bytes
    if len(t) >= 2:
        # Zlib: 0x78 0x9C or 0x78 0xDA
        if t.startswith('x\x9c') or t.startswith('x\xda'):
            hints.append("Zlib compressed data (magic bytes)")
        # Gzip: 0x1F 0x8B
        if t.startswith('\x1f\x8b'):
            hints.append("Gzip compressed data (magic bytes)")
        # Bzip2: 'BZh'
        if t.startswith('BZh'):
            hints.append("Bzip2 compressed data (magic bytes)")

    # PNG magic bytes
    if len(t) >= 8 and t.startswith('\x89PNG\r\n\x1a\n'):
        hints.append("PNG image (magic bytes)")

    # JPG magic bytes
    if len(t) >= 3 and t.startswith('\xff\xd8\xff'):
        hints.append("JPEG image (magic bytes)")

    # ZIP magic bytes
    if len(t) >= 4 and t.startswith('PK\x03\x04'):
        hints.append("ZIP archive (magic bytes)")

    # PDF magic bytes
    if len(t) >= 4 and t.startswith('%PDF'):
        hints.append("PDF document (magic bytes)")

    # ELF magic bytes
    if len(t) >= 4 and t.startswith('\x7fELF'):
        hints.append("ELF executable (magic bytes)")

    # --- Content-based hints ---

    # HTML/XML
    if '<' in t and '>' in t and ('html' in t.lower() or 'xml' in t.lower()):
        hints.append("possible HTML/XML content")

    # JSON
    if t.startswith('{') and t.endswith('}') and '"' in t:
        hints.append("possible JSON content")

    # YAML
    if (':' in t or '-' in t) and ('\n' in t or len(t.split()) > 3):
        hints.append("possible YAML content")

    # --- Encoding-specific ---

    # UUEncode
    if t.startswith('begin ') and ' ' in t[:20]:
        hints.append("possible UUEncode format")

    # yEnc
    if '=ybegin' in t.lower() or '=ypart' in t.lower() or '=yend' in t.lower():
        hints.append("possible yEnc format")

    # Punycode
    if t.startswith('xn--'):
        hints.append("possible Punycode (IDN)")

    # UTF-7
    if '+' in t and '-' in t and re.search(r'\+[A-Za-z0-9+/]+-', t):
        hints.append("possible UTF-7 encoding")

    # --- Cipher-specific ---

    # ADFGVX/ADFGX
    if re.fullmatch(r'[ADFGVX]+', clean, re.IGNORECASE):
        hints.append("possible ADFGVX/ADFGX cipher")

    # Bifid/Trifid
    if re.fullmatch(r'[A-Z\d\.\s]+', t, re.IGNORECASE) and len(t) > 10:
        hints.append("possible Bifid/Trifid cipher")

    # Polybius
    if re.fullmatch(r'[1-5\s]+', t) and len(t.replace(' ', '')) % 2 == 0:
        hints.append("possible Polybius square cipher")

    # Tap code
    if re.fullmatch(r'(\.+\s\.+\s*)+', t):
        hints.append("possible Tap code")

    # --- Prioritization hints ---
    if len(hints) > 1:
        # If multiple hints, prioritize based on confidence
        priority_hints = []
        if "JWT structure" in hints:
            priority_hints.append("JWT structure (high confidence)")
        if "PEM/DER format" in hints:
            priority_hints.append("PEM/DER format (high confidence)")
        if "Zlib compressed data" in hints or "Gzip compressed data" in hints or "Bzip2 compressed data" in hints:
            priority_hints.append("Compressed data (high confidence)")
        if "PNG image" in hints or "JPEG image" in hints or "ZIP archive" in hints or "PDF document" in hints:
            priority_hints.append("Binary file format (high confidence)")
        if priority_hints:
            return priority_hints

    return hints