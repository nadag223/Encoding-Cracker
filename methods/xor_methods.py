"""XOR methods: single-byte brute force (0x00–0xFF) + keyword XOR + multi-byte XOR + known-plaintext XOR + bit rotation."""
import itertools
from collections import Counter

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_single_byte(text: str, key_byte: int):
    """XOR text with a single byte key"""
    try:
        raw = text.encode('latin-1', errors='replace')
        return _xor_bytes(raw, bytes([key_byte])).decode('latin-1', errors='replace')
    except Exception:
        return None

def xor_key_keyword(text: str, keyword: str):
    try:
        raw = text.encode('latin-1', errors='replace')
        key = keyword.encode('utf-8')
        return _xor_bytes(raw, key).decode('latin-1', errors='replace')
    except Exception:
        return None

# ── Multi-byte XOR with Kasiski/Frequency Analysis ────────────────────────────

# Common file magic bytes for known-plaintext attack
MAGIC_BYTES = {
    'PNG': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    'JPG': bytes([0xFF, 0xD8, 0xFF]),
    'PDF': bytes([0x25, 0x50, 0x44, 0x46]),
    'ZIP': bytes([0x50, 0x4B, 0x03, 0x04]),
    'GZIP': bytes([0x1F, 0x8B]),
    'BZIP2': bytes([0x42, 0x5A, 0x68]),
    'RAR': bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]),
    'ELF': bytes([0x7F, 0x45, 0x4C, 0x46]),
    'MACHO': bytes([0xFE, 0xED, 0xFA, 0xCE]),
    'CLASS': bytes([0xCA, 0xFE, 0xBA, 0xBE]),
}

# English letter frequencies for scoring
EN_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
    'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
    'P': 1.93, 'B': 1.49, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07, ' ': 13.00,
}

def _kasiski_examination(text: bytes, min_len: int = 3, max_len: int = 8) -> dict[int, int]:
    """Find repeated sequences and their distances to estimate key length."""
    sequences = {}
    for i in range(len(text) - min_len):
        for length in range(min_len, max_len + 1):
            if i + length > len(text):
                break
            seq = text[i:i+length]
            if seq in sequences:
                sequences[seq].append(i)
            else:
                sequences[seq] = [i]
    # Count distances between occurrences
    distances = Counter()
    for positions in sequences.values():
        if len(positions) > 1:
            for i in range(len(positions)):
                for j in range(i + 1, len(positions)):
                    dist = positions[j] - positions[i]
                    # Factor the distance
                    for k in range(2, 17):
                        if dist % k == 0:
                            distances[k] += 1
    return distances

def _frequency_score(text: bytes) -> float:
    """Score bytes based on English letter frequency."""
    score = 0
    for b in text:
        c = chr(b).upper()
        score += EN_FREQ.get(c, -1)
    return score / max(len(text), 1)

def _find_key_length_kasiski(data: bytes) -> list[int]:
    """Find likely key lengths using Kasiski examination."""
    distances = _kasiski_examination(data)
    # Sort by frequency
    sorted_lengths = sorted(distances.keys(), key=lambda k: distances[k], reverse=True)
    # Filter to reasonable lengths
    return [k for k in sorted_lengths if 2 <= k <= 16][:5]

def _find_key_length_ic(data: bytes, max_len: int = 16) -> list[int]:
    """Find likely key lengths using Index of Coincidence."""
    best_lengths = []
    for key_len in range(2, max_len + 1):
        ic_sum = 0
        for offset in range(key_len):
            slice_bytes = data[offset::key_len]
            if len(slice_bytes) < 2:
                continue
            freq = Counter(slice_bytes)
            n = len(slice_bytes)
            ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
            ic_sum += ic
        avg_ic = ic_sum / key_len if key_len > 0 else 0
        # English IC ~ 0.067, random ~ 0.038
        if avg_ic > 0.05:
            best_lengths.append((key_len, avg_ic))
    best_lengths.sort(key=lambda x: x[1], reverse=True)
    return [k for k, _ in best_lengths[:5]]

def _recover_xor_key(data: bytes, key_len: int) -> bytes | None:
    """Recover XOR key of given length using frequency analysis on each position."""
    key = bytearray()
    for i in range(key_len):
        slice_bytes = data[i::key_len]
        if not slice_bytes:
            return None
        best_score = -float('inf')
        best_byte = 0
        for key_byte in range(256):
            decrypted = bytes(b ^ key_byte for b in slice_bytes)
            score = _frequency_score(decrypted)
            if score > best_score:
                best_score = score
                best_byte = key_byte
        key.append(best_byte)
    return bytes(key)

def xor_multi_byte_kasiski(text: str) -> str | None:
    """Multi-byte XOR using Kasiski + frequency analysis."""
    try:
        raw = text.encode('latin-1', errors='replace')
        if len(raw) < 20:
            return None

        # Find likely key lengths
        kasiski_lengths = _find_key_length_kasiski(raw)
        ic_lengths = _find_key_length_ic(raw)

        # Combine and deduplicate
        candidates = []
        for l in kasiski_lengths + ic_lengths:
            if l not in candidates:
                candidates.append(l)

        if not candidates:
            candidates = list(range(2, 9))  # fallback

        best_result = None
        best_score = -float('inf')

        for key_len in candidates[:5]:  # Try top 5
            key = _recover_xor_key(raw, key_len)
            if key:
                result = _xor_bytes(raw, key).decode('latin-1', errors='replace')
                score = _frequency_score(result.encode('latin-1', errors='replace'))
                if score > best_score:
                    best_score = score
                    best_result = result

        return best_result
    except Exception:
        return None

# ── Known-plaintext XOR (magic bytes) ────────────────────────────────────────

def xor_known_plaintext(text: str) -> str | None:
    """Try to derive XOR key from known file magic bytes."""
    try:
        raw = text.encode('latin-1', errors='replace')
        if len(raw) < 8:
            return None

        best_result = None
        best_score = -float('inf')

        for name, magic in MAGIC_BYTES.items():
            if len(raw) < len(magic):
                continue
            # Derive key from first len(magic) bytes
            derived_key = bytes(raw[i] ^ magic[i] for i in range(len(magic)))

            # Try key lengths that are multiples of magic length
            for key_len in [len(magic), len(magic) * 2, len(magic) * 3]:
                if key_len > 32:
                    break
                # Extend key by repeating
                full_key = (derived_key * (key_len // len(derived_key) + 1))[:key_len]
                result = _xor_bytes(raw, full_key).decode('latin-1', errors='replace')
                score = _frequency_score(result.encode('latin-1', errors='replace'))
                if score > best_score:
                    best_score = score
                    best_result = result

        return best_result
    except Exception:
        return None

# ── Bit rotation (ROL/ROR) ────────────────────────────────────────────────────

def rol_byte(b: int, n: int) -> int:
    """Rotate left 8-bit value."""
    n = n % 8
    return ((b << n) & 0xFF) | (b >> (8 - n))

def ror_byte(b: int, n: int) -> int:
    """Rotate right 8-bit value."""
    n = n % 8
    return (b >> n) | ((b << (8 - n)) & 0xFF)

def rol_bits(text: str, n: int):
    """Rotate bits left by n positions"""
    try:
        raw = text.encode('latin-1', errors='replace')
        return bytes(rol_byte(b, n) for b in raw).decode('latin-1', errors='replace')
    except Exception:
        return None

def ror_bits(text: str, n: int):
    """Rotate bits right by n positions"""
    try:
        raw = text.encode('latin-1', errors='replace')
        return bytes(ror_byte(b, n) for b in raw).decode('latin-1', errors='replace')
    except Exception:
        return None

def _make_rol(n: int):
    def fn(text: str):
        return rol_bits(text, n)
    return fn

def _make_ror(n: int):
    def fn(text: str):
        return ror_bits(text, n)
    return fn

def get_methods():
    methods = []
    # XOR with every single byte
    for b in range(256):
        methods.append((f"XOR key=0x{b:02X}", "xor_single", b))
    # XOR with common keywords
    for kw in ["key", "flag", "secret", "password", "admin", "crypto", "ctf"]:
        methods.append((f"XOR key='{kw}'", "xor_keyword", kw))
    # Multi-byte XOR with Kasiski/frequency analysis
    methods.append(("XOR Multi-byte (Kasiski/Freq)", "xor_multi", None))
    # Known-plaintext XOR (magic bytes)
    methods.append(("XOR Known-Plaintext (Magic Bytes)", "xor_known", None))
    # Bit rotation ROL 1-7
    for n in range(1, 8):
        methods.append((f"ROL {n} bits", "rol", n))
    # Bit rotation ROR 1-7
    for n in range(1, 8):
        methods.append((f"ROR {n} bits", "ror", n))
    return methods