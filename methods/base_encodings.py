"""Base encodings: Base16 through Base91, hex, binary, octal, decimal, BCD, etc."""
import base64
import binascii

# ── helpers ──────────────────────────────────────────────────────────────────

def _safe_decode(b: bytes) -> str:
    try:
        return b.decode('utf-8')
    except Exception:
        return b.decode('latin-1', errors='replace')

# ── Base encodings ────────────────────────────────────────────────────────────

def base16_decode(text: str):
    try:
        return _safe_decode(base64.b16decode(text.upper()))
    except Exception:
        return None

def base32_decode(text: str):
    try:
        pad = text.upper() + '=' * (-len(text) % 8)
        return _safe_decode(base64.b32decode(pad))
    except Exception:
        return None

def base32hex_decode(text: str):
    try:
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUV'
        std   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        t = text.upper().translate(str.maketrans(chars, std))
        pad = t + '=' * (-len(t) % 8)
        return _safe_decode(base64.b32decode(pad))
    except Exception:
        return None

def base45_decode(text: str):
    # Base45 alphabet
    try:
        ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
        t = text.strip()
        res = []
        for i in range(0, len(t) - 1, 3):
            chunk = t[i:i+3]
            if len(chunk) == 2:
                n = ALPHABET.index(chunk[0]) + ALPHABET.index(chunk[1]) * 45
                res.append(n)
            else:
                c, d, e = (ALPHABET.index(x) for x in chunk)
                n = c + d * 45 + e * 45 * 45
                res.append(n >> 8)
                res.append(n & 0xFF)
        return _safe_decode(bytes(res))
    except Exception:
        return None

def base58_decode(text: str):
    # Bitcoin Base58 alphabet
    try:
        ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for c in text.strip():
            n = n * 58 + ALPHA.index(c)
        result = []
        while n:
            result.append(n & 0xFF)
            n >>= 8
        result.reverse()
        leading = len(text) - len(text.lstrip('1'))
        return _safe_decode(bytes(leading) + bytes(result))
    except Exception:
        return None

def base62_decode(text: str):
    try:
        ALPHA = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        n = 0
        for c in text.strip():
            n = n * 62 + ALPHA.index(c)
        result = []
        while n:
            result.append(n & 0xFF)
            n >>= 8
        result.reverse()
        return _safe_decode(bytes(result))
    except Exception:
        return None

def base64_standard_decode(text: str):
    try:
        pad = text + '=' * (-len(text) % 4)
        return _safe_decode(base64.b64decode(pad))
    except Exception:
        return None

def base64_urlsafe_nopad_decode(text: str):
    try:
        pad = text + '=' * (-len(text) % 4)
        return _safe_decode(base64.urlsafe_b64decode(pad))
    except Exception:
        return None

def base64_urlsafe_pad_decode(text: str):
    try:
        return _safe_decode(base64.urlsafe_b64decode(text))
    except Exception:
        return None

def base85_rfc_decode(text: str):
    try:
        return _safe_decode(base64.b85decode(text))
    except Exception:
        return None

def base85_ascii85_decode(text: str):
    try:
        return _safe_decode(base64.a85decode(text))
    except Exception:
        return None

def base91_decode(text: str):
    # Pure Python Base91
    try:
        TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        v = -1; b = 0; n = 0; o = []
        for c in text:
            if c not in TABLE:
                continue
            p = TABLE.index(c)
            if v < 0:
                v = p
            else:
                v += p * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                v = -1
                while n > 7:
                    o.append(b & 255)
                    b >>= 8
                    n -= 8
        if v > -1:
            o.append((b | v << n) & 255)
        return _safe_decode(bytes(o))
    except Exception:
        return None

# ── Binary & Numeric ─────────────────────────────────────────────────────────

def binary_spaces_decode(text: str):
    try:
        parts = text.strip().split()
        return ''.join(chr(int(b, 2)) for b in parts)
    except Exception:
        return None

def binary_nospaces_decode(text: str):
    try:
        t = text.replace(' ', '')
        return ''.join(chr(int(t[i:i+8], 2)) for i in range(0, len(t) - 7, 8))
    except Exception:
        return None

def octal_decode(text: str):
    try:
        parts = text.strip().split()
        return ''.join(chr(int(p, 8)) for p in parts)
    except Exception:
        return None

def decimal_decode(text: str):
    try:
        parts = text.strip().split()
        return ''.join(chr(int(p)) for p in parts)
    except Exception:
        return None

def hex_raw_decode(text: str):
    try:
        return _safe_decode(bytes.fromhex(text.replace(' ', '')))
    except Exception:
        return None

def bcd_decode(text: str):
    # BCD: each pair of decimal digits → one byte value
    try:
        t = text.replace(' ', '')
        result = []
        for i in range(0, len(t) - 1, 2):
            high = int(t[i])
            low  = int(t[i+1])
            result.append(high * 16 + low)
        return _safe_decode(bytes(result))
    except Exception:
        return None

def bigint_to_bytes_decode(text: str):
    try:
        n = int(text.strip())
        length = (n.bit_length() + 7) // 8
        return _safe_decode(n.to_bytes(length, 'big'))
    except Exception:
        return None

def little_endian_hex_decode(text: str):
    try:
        raw = bytes.fromhex(text.replace(' ', ''))
        return _safe_decode(raw[::-1])
    except Exception:
        return None

def base92_decode(text: str):
    # dcode.fr Base92: 91-char alphabet (no backtick!), ~ = empty string
    try:
        t = text.strip()

        if t == '~':
            return ''

        TABLE = '!#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}'

        # סנן רק תווים חוקיים
        t = ''.join(c for c in t if c in TABLE)

        bits = 0
        num_bits = 0
        result = []
        i = 0

        while i < len(t):
            if i + 1 < len(t):
                a = TABLE.index(t[i])
                b = TABLE.index(t[i + 1])
                val = a * 91 + b
                bits = (bits << 13) | val
                num_bits += 13
                i += 2
            else:
                a = TABLE.index(t[i])
                bits = (bits << 6) | a
                num_bits += 6
                i += 1

            while num_bits >= 8:
                num_bits -= 8
                result.append((bits >> num_bits) & 0xFF)

        return _safe_decode(bytes(result))
    except Exception:
        return None

# ── Method registry ───────────────────────────────────────────────────────────

def get_methods():
    return [
        ("Base16/Hex Decode",           base16_decode),
        ("Base32 Standard Decode",      base32_decode),
        ("Base32 Hex Decode",           base32hex_decode),
        ("Base45 Decode",               base45_decode),
        ("Base58 Bitcoin Decode",       base58_decode),
        ("Base62 Decode",               base62_decode),
        ("Base64 Standard Decode",      base64_standard_decode),
        ("Base64 URL-safe No-pad",      base64_urlsafe_nopad_decode),
        ("Base64 URL-safe With-pad",    base64_urlsafe_pad_decode),
        ("Base85 RFC1924 Decode",       base85_rfc_decode),
        ("Base85 ASCII85/Adobe Decode", base85_ascii85_decode),
        ("Base91 Decode",               base91_decode),
        ("Base92 Decode",               base92_decode),
        ("Binary → ASCII (spaces)",     binary_spaces_decode),
        ("Binary → ASCII (no spaces)",  binary_nospaces_decode),
        ("Octal → ASCII",               octal_decode),
        ("Decimal → ASCII",             decimal_decode),
        ("Hex → ASCII (raw)",           hex_raw_decode),
        ("BCD Decode",                  bcd_decode),
        ("BigInt → Bytes",              bigint_to_bytes_decode),
        ("Little-Endian Hex Decode",    little_endian_hex_decode),
    ]