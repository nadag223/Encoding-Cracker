"""Classic substitution ciphers: Atbash, Vigenere, Beaufort, Affine, Bacon, Polybius, Tap, Playfair."""
import math

VIGENERE_KEYS = ["key","flag","ctf","secret","password",
                 "crypto","hack","admin","abc","xyz","leet","cipher"]

# ── Atbash ────────────────────────────────────────────────────────────────────

def atbash_latin(text: str):
    try:
        result = []
        for c in text:
            if c.isupper(): result.append(chr(ord('Z') - (ord(c) - ord('A'))))
            elif c.islower(): result.append(chr(ord('z') - (ord(c) - ord('a'))))
            else: result.append(c)
        return ''.join(result)
    except Exception:
        return None

def atbash_hebrew(text: str):
    # Treat a-z as alef-tav positions (same math)
    return atbash_latin(text)

# ── Vigenere ──────────────────────────────────────────────────────────────────

def _vigenere(text: str, key: str, decrypt: bool = True) -> str:
    key = key.lower()
    result = []; ki = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('a')
            shift = -k if decrypt else k
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def _beaufort(text: str, key: str) -> str:
    key = key.lower()
    result = []; ki = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('a')
            result.append(chr((k - (ord(c) - base)) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

# ── Affine ────────────────────────────────────────────────────────────────────

def _modinv(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def _affine_decrypt(text: str, a: int, b: int) -> str:
    inv_a = _modinv(a, 26)
    if inv_a is None:
        return None
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((inv_a * (ord(c) - base - b)) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

# ── Bacon ─────────────────────────────────────────────────────────────────────

_BACON_AB = {
    'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E',
    'AABAB':'F','AABBA':'G','AABBB':'H','ABAAA':'I','ABAAB':'J',
    'ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O',
    'ABBBB':'P','BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T',
    'BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X','BBAAA':'Y','BBAAB':'Z'
}
_BACON_01 = {k.replace('A','0').replace('B','1'):v for k,v in _BACON_AB.items()}

def bacon_ab_decode(text: str):
    try:
        t = ''.join(c.upper() for c in text if c.upper() in 'AB')
        return ''.join(_BACON_AB.get(t[i:i+5],'?') for i in range(0, len(t)-4, 5))
    except Exception:
        return None

def bacon_01_decode(text: str):
    try:
        t = ''.join(c for c in text if c in '01')
        return ''.join(_BACON_01.get(t[i:i+5],'?') for i in range(0, len(t)-4, 5))
    except Exception:
        return None

# ── Polybius ──────────────────────────────────────────────────────────────────

def polybius_decode(text: str):
    try:
        grid = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # I=J
        pairs = text.replace(' ','')
        result = []
        for i in range(0, len(pairs)-1, 2):
            row = int(pairs[i]) - 1
            col = int(pairs[i+1]) - 1
            result.append(grid[row*5 + col])
        return ''.join(result)
    except Exception:
        return None

# ── Tap code ──────────────────────────────────────────────────────────────────

def tap_decode(text: str):
    try:
        grid = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        groups = text.strip().split('  ')
        result = []
        for g in groups:
            parts = g.strip().split(' ')
            if len(parts) == 2:
                row = parts[0].count('.') - 1
                col = parts[1].count('.') - 1
                result.append(grid[row*5 + col])
        return ''.join(result)
    except Exception:
        return None

# ── Playfair ──────────────────────────────────────────────────────────────────

def _make_playfair_grid(key: str):
    key = key.upper().replace('J','I')
    seen = set(); grid = []
    for c in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seen and c.isalpha():
            seen.add(c); grid.append(c)
    return grid

def _playfair_decrypt(text: str, key: str):
    grid = _make_playfair_grid(key)
    pos  = {c:(i//5, i%5) for i,c in enumerate(grid)}
    t = text.upper().replace('J','I').replace(' ','')
    if len(t) % 2 != 0:
        return None
    result = []
    for i in range(0, len(t), 2):
        a, b = t[i], t[i+1]
        ra,ca = pos[a]; rb,cb = pos[b]
        if ra == rb:
            result += [grid[ra*5+(ca-1)%5], grid[rb*5+(cb-1)%5]]
        elif ca == cb:
            result += [grid[((ra-1)%5)*5+ca], grid[((rb-1)%5)*5+cb]]
        else:
            result += [grid[ra*5+cb], grid[rb*5+ca]]
    return ''.join(result)

# ── Method registry ───────────────────────────────────────────────────────────

def get_methods():
    methods = []

    methods.append(("Atbash Latin", atbash_latin))
    methods.append(("Atbash Hebrew (transliterated)", atbash_hebrew))

    for k in VIGENERE_KEYS:
        key = k
        methods.append((f"Vigenere key={k}", lambda t, kk=key: _vigenere(t, kk)))

    for k in VIGENERE_KEYS:
        key = k
        methods.append((f"Beaufort key={k}", lambda t, kk=key: _beaufort(t, kk)))

    # Affine: all valid a values (coprime to 26)
    for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
        for b in range(0, 26, 5):
            aa, bb = a, b
            methods.append((f"Affine a={a} b={b}", lambda t, a=aa, b=bb: _affine_decrypt(t, a, b)))

    methods.append(("Bacon A/B Decode", bacon_ab_decode))
    methods.append(("Bacon 0/1 Decode", bacon_01_decode))
    methods.append(("Polybius Square Decode", polybius_decode))
    methods.append(("Tap Code Decode", tap_decode))

    for k in ["playfair","keyword","secret"]:
        key = k
        methods.append((f"Playfair key={k}", lambda t, kk=key: _playfair_decrypt(t, kk)))

    return methods
