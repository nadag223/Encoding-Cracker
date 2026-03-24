"""XOR methods: single-byte brute force (0x00–0xFF) + keyword XOR."""

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def _make_xor_single(key_byte: int):
    def fn(text: str):
        try:
            raw = text.encode('latin-1', errors='replace')
            return _xor_bytes(raw, bytes([key_byte])).decode('latin-1', errors='replace')
        except Exception:
            return None
    return fn

def xor_key_keyword(text: str, keyword: str):
    try:
        raw = text.encode('latin-1', errors='replace')
        key = keyword.encode('utf-8')
        return _xor_bytes(raw, key).decode('latin-1', errors='replace')
    except Exception:
        return None

def get_methods():
    methods = []
    # XOR with every single byte
    for b in range(256):
        methods.append((f"XOR key=0x{b:02X}", _make_xor_single(b)))
    # XOR with common keywords
    for kw in ["key", "flag"]:
        k = kw
        methods.append((f"XOR key='{kw}'", lambda t, kk=k: xor_key_keyword(t, kk)))
    return methods
