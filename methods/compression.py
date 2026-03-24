"""Compression & MIME: zlib, gzip, bzip2, quoted-printable, MIME header decode."""
import base64
import zlib
import gzip
import bz2
import quopri
import email.header

def _try_decompress(raw: bytes, method) -> str | None:
    try:
        return method(raw).decode('utf-8', errors='replace')
    except Exception:
        return None

def _get_raw(text: str) -> bytes | None:
    """Try to interpret text as hex or base64 bytes."""
    try:
        return bytes.fromhex(text.replace(' ', ''))
    except Exception:
        pass
    try:
        pad = text + '=' * (-len(text) % 4)
        return base64.b64decode(pad)
    except Exception:
        pass
    return text.encode('latin-1', errors='replace')

def zlib_decompress(text: str):
    raw = _get_raw(text)
    if raw is None:
        return None
    return _try_decompress(raw, zlib.decompress)

def gzip_decompress(text: str):
    raw = _get_raw(text)
    if raw is None:
        return None
    return _try_decompress(raw, lambda d: gzip.decompress(d))

def bzip2_decompress(text: str):
    raw = _get_raw(text)
    if raw is None:
        return None
    return _try_decompress(raw, bz2.decompress)

def quoted_printable_decode(text: str):
    try:
        return quopri.decodestring(text.encode()).decode('utf-8', errors='replace')
    except Exception:
        return None

def mime_header_decode(text: str):
    try:
        parts = email.header.decode_header(text)
        result = []
        for chunk, enc in parts:
            if isinstance(chunk, bytes):
                result.append(chunk.decode(enc or 'utf-8', errors='replace'))
            else:
                result.append(str(chunk))
        return ''.join(result)
    except Exception:
        return None

def lzw_basic_decode(text: str):
    # Minimal LZW: expects space-separated decimal codes
    try:
        codes = list(map(int, text.strip().split()))
        table = {i: chr(i) for i in range(256)}
        result = [table[codes[0]]]; prev = table[codes[0]]
        for code in codes[1:]:
            if code in table:
                entry = table[code]
            else:
                entry = prev + prev[0]
            result.append(entry)
            table[len(table)] = prev + entry[0]
            prev = entry
        return ''.join(result)
    except Exception:
        return None

def get_methods():
    return [
        ("Zlib Decompress",           zlib_decompress),
        ("Gzip Decompress",           gzip_decompress),
        ("Bzip2 Decompress",          bzip2_decompress),
        ("Quoted-Printable Decode",   quoted_printable_decode),
        ("MIME Header Decode",        mime_header_decode),
        ("LZW Basic Decode",          lzw_basic_decode),
    ]
