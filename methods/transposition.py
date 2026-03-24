"""Transposition ciphers: Rail Fence, columnar transposition, reverse variants, every-Nth."""
from itertools import permutations

# ── Rail Fence ────────────────────────────────────────────────────────────────

def _rail_fence_decode(text: str, rails: int) -> str:
    n = len(text)
    indices = list(range(n))
    pattern = []
    # build rail pattern
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    # sort indices by rail
    order = sorted(range(n), key=lambda i: pattern[i])
    result = [''] * n
    for pos, char in zip(order, text):
        result[pos] = char
    return ''.join(result)

def rail_fence_2(text: str): return _rail_fence_decode(text, 2)
def rail_fence_3(text: str): return _rail_fence_decode(text, 3)
def rail_fence_4(text: str): return _rail_fence_decode(text, 4)
def rail_fence_5(text: str): return _rail_fence_decode(text, 5)

# ── Columnar transposition ────────────────────────────────────────────────────

def _columnar_decrypt(text: str, key_order: tuple) -> str:
    try:
        n_cols = len(key_order)
        n_rows = len(text) // n_cols
        remainder = len(text) % n_cols
        col_lengths = [n_rows + (1 if i < remainder else 0) for i in range(n_cols)]
        # re-order columns according to key
        cols = {}; pos = 0
        for col_idx in sorted(range(n_cols), key=lambda x: key_order[x]):
            cols[col_idx] = text[pos:pos+col_lengths[col_idx]]
            pos += col_lengths[col_idx]
        result = []
        for r in range(n_rows + (1 if remainder else 0)):
            for c in range(n_cols):
                if r < len(cols[c]):
                    result.append(cols[c][r])
        return ''.join(result)
    except Exception:
        return None

# ── Simple reverse methods ────────────────────────────────────────────────────

def reverse_string(text: str):   return text[::-1]
def reverse_words(text: str):    return ' '.join(text.split()[::-1])
def reverse_each_word(text: str):return ' '.join(w[::-1] for w in text.split())
def even_chars(text: str):       return text[::2]
def odd_chars(text: str):        return text[1::2]

# ── Method registry ───────────────────────────────────────────────────────────

def get_methods():
    methods = [
        ("Rail Fence 2 rails", rail_fence_2),
        ("Rail Fence 3 rails", rail_fence_3),
        ("Rail Fence 4 rails", rail_fence_4),
        ("Rail Fence 5 rails", rail_fence_5),
    ]

    # Columnar transposition for key lengths 2 and 3
    for perm in permutations(range(2)):
        p = perm
        methods.append((f"Columnar key-len=2 order={p}", lambda t, pp=p: _columnar_decrypt(t, pp)))
    for perm in permutations(range(3)):
        p = perm
        methods.append((f"Columnar key-len=3 order={p}", lambda t, pp=p: _columnar_decrypt(t, pp)))

    methods += [
        ("Reverse String",         reverse_string),
        ("Reverse Words",          reverse_words),
        ("Reverse Each Word",      reverse_each_word),
        ("Even-Index Chars",       even_chars),
        ("Odd-Index Chars",        odd_chars),
    ]
    return methods
