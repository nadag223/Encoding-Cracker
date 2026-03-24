"""String pattern tricks: first/last letter, every-Nth char, steganography, homoglyphs."""
import re
import unicodedata

# ── Letter extraction ─────────────────────────────────────────────────────────

def first_letters(text: str):
    words = text.split()
    return ''.join(w[0] for w in words if w) or None

def last_letters(text: str):
    words = text.split()
    return ''.join(w[-1] for w in words if w) or None

def every_2nd(text: str):  return text[::2] or None
def every_3rd(text: str):  return text[::3] or None
def every_4th(text: str):  return text[::4] or None
def every_5th(text: str):  return text[::5] or None

def split_5chars(text: str):
    t = text.replace(' ', '')
    return ' '.join(t[i:i+5] for i in range(0, len(t), 5)) or None

def read_diagonal(text: str):
    try:
        lines = text.splitlines()
        if len(lines) < 2:
            return None
        return ''.join(lines[i][i] for i in range(min(len(lines), len(lines[0]))))
    except Exception:
        return None

def interleave_even(text: str): return text[::2] or None
def interleave_odd(text: str):  return text[1::2] or None

# ── Zero-width & steganography ────────────────────────────────────────────────

ZERO_WIDTH = {'\u200b', '\ufeff', '\u200c', '\u200d'}

def remove_zero_width(text: str):
    result = ''.join(c for c in text if c not in ZERO_WIDTH)
    return result if result != text else None

def whitespace_stego(text: str):
    # Convert spaces (0) and tabs (1) to binary, then to ASCII
    try:
        bits = ''.join('1' if c == '\t' else '0' for c in text if c in ' \t')
        if not bits:
            return None
        return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8))
    except Exception:
        return None

def null_byte_remove(text: str):
    result = text.replace('\x00', '')
    return result if result != text else None

# ── Unicode normalization ─────────────────────────────────────────────────────

def homoglyph_normalize(text: str):
    try:
        return unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')
    except Exception:
        return None

# ── Math / ADD / SUB / Multiplicative ciphers ─────────────────────────────────

def _add_cipher(text: str, offset: int):
    return ''.join(chr((ord(c) + offset) % 128) if ord(c) < 128 else c for c in text)

def _sub_cipher(text: str, offset: int):
    return _add_cipher(text, -offset)

def _mult_cipher(text: str, a: int):
    import math
    inv = None
    for i in range(1, 26):
        if (a * i) % 26 == 1:
            inv = i; break
    if inv is None:
        return None
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((inv * (ord(c) - base)) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

# ── Method registry ───────────────────────────────────────────────────────────

def get_methods():
    methods = [
        ("First Letter of Each Word",   first_letters),
        ("Last Letter of Each Word",    last_letters),
        ("Every 2nd Char",              every_2nd),
        ("Every 3rd Char",              every_3rd),
        ("Every 4th Char",              every_4th),
        ("Every 5th Char",              every_5th),
        ("Split at 5-char Intervals",   split_5chars),
        ("Diagonal Read",               read_diagonal),
        ("Interleaved Even Chars",      interleave_even),
        ("Interleaved Odd Chars",       interleave_odd),
        ("Zero-Width Char Removal",     remove_zero_width),
        ("Whitespace Steganography",    whitespace_stego),
        ("Null Byte Removal",           null_byte_remove),
        ("Homoglyph Normalize",         homoglyph_normalize),
    ]

    # ADD cipher: offsets 1–127
    for offset in range(1, 128):
        o = offset
        methods.append((f"ADD cipher offset={offset}", lambda t, oo=o: _add_cipher(t, oo)))

    # SUB cipher: offsets 1–127
    for offset in range(1, 128):
        o = offset
        methods.append((f"SUB cipher offset={offset}", lambda t, oo=o: _sub_cipher(t, oo)))

    # Multiplicative cipher: all coprime a values mod 26
    for a in [3,5,7,9,11,15,17,19,21,23,25]:
        aa = a
        methods.append((f"Multiplicative a={a}", lambda t, aa=aa: _mult_cipher(t, aa)))

    return methods
