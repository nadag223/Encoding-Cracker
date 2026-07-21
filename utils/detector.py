"""Auto-detects the most likely encoding of the input string with structural fingerprinting.

This module exposes two public surfaces:

  * ``detect(text)``        — returns a list of human-readable heuristic hints (used by
                             the CLI for the ``[*] Auto-detected:`` lines).
  * ``get_structural_signals(text)`` — returns a normalized dict of *binary structural
                             signals* (each 0.0 or 1.0) consumed by the confidence
                             scorer. Only genuinely valid structures set a flag; loose
                             substring checks never set ``strong_structural_match``.

The scorer treats ``strong_structural_match`` as a dominant signal (it short-circuits
to a high base score), so these detectors must be precise — a false positive here
would inflate gibberish results, which is exactly the bug this rework fixes.
"""
import re
import string
import base64

# ── TLD list ─────────────────────────────────────────────────────────────────
# A reasonably complete but bounded list of top-level domains relevant to CTF
# contexts: common gTLDs and the ccTLDs that show up in real flag/footer material.
# This is deliberately NOT exhaustive (the real root has ~1500 TLDs); it just
# needs common ones plus country codes seen in likely CTF contexts.
_TLDS = [
    # generic
    'com', 'org', 'net', 'io', 'co', 'gov', 'edu', 'mil', 'int', 'info', 'biz',
    'name', 'pro', 'dev', 'app', 'xyz', 'tech', 'online', 'site', 'cloud', 'run',
    'ai', 'me', 'cc', 'tv', 'club', 'top', 'store', 'shop', 'news', 'blog', 'zone',
    'page', 'live', 'world', 'systems', 'security',
    # country codes
    'il', 'us', 'uk', 'de', 'fr', 'ru', 'cn', 'jp', 'kr', 'in', 'br', 'ca', 'au',
    'it', 'es', 'nl', 'se', 'no', 'fi', 'dk', 'pl', 'cz', 'be', 'ch', 'at', 'tr',
    'gr', 'pt', 'ie', 'mx', 'ar', 'za', 'eg', 'sa', 'ae', 'ir', 'hk', 'tw', 'sg',
    'my', 'th', 'id', 'vn', 'nz', 'ua', 'ro', 'hu', 'sk', 'si', 'hr', 'lt', 'lv',
    'ee', 'bg', 'rs', 'ph', 'pk', 'bd', 'ng', 'ke',
]
_TLD_ALTERNATION = '|'.join(sorted(set(_TLDS), key=len, reverse=True))

# A full valid domain: one-or-more dot-separated labels (letters/digits/hyphens,
# not starting or ending in a hyphen, max 63 chars each) followed by a known TLD.
# Anchored: the *whole* candidate must BE a valid domain (modulo stray whitespace
# and a leading scheme), not merely contain a dot. This is what stops gibberish
# like "WT.MH#F(L]B7KI+N2?1^NF4II" — whose "WT.MH" looks dot-ish — from matching:
# "MH#F(L]B7KI+N2?1^NF4II" is not a valid label and there is no valid TLD.
DOMAIN_PATTERN = re.compile(
    r'^\s*'                                     # optional leading whitespace
    r'(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?'          # optional scheme http:// https:// etc.
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:' + _TLD_ALTERNATION + r')'            # known TLD (no trailing dot)
    r'(?:/[^\s]*)?'                             # optional path
    r'\s*$',
    re.IGNORECASE,
)

# JWT: three base64url segments separated by dots (header.payload.signature).
# Each segment must be non-empty base64url; we do not require valid JSON to keep
# the check structural + cheap, but we do require all three segments present.
_JWT_PATTERN = re.compile(
    r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
)

# PEM block: -----BEGIN <TYPE>----- ... -----END <TYPE>-----
_PEM_PATTERN = re.compile(
    r'^-----BEGIN [A-Z0-9 ]+-----[\s\S]*-----END [A-Z0-9 ]+-----$'
)

# Magic-byte fingerprints, matched against raw text chars. These are intentionally
# narrow (exact magic prefixes) so they cannot fire on lookalike gibberish.
_MAGIC_PATTERNS = [
    ('png',    lambda t: t.startswith('\x89PNG\r\n\x1a\n')),
    ('jpg',    lambda t: t.startswith('\xff\xd8\xff')),
    ('zip',    lambda t: t.startswith('PK\x03\x04')),
    ('pdf',    lambda t: t.startswith('%PDF')),
    ('elf',    lambda t: t.startswith('\x7fELF')),
    ('gzip',   lambda t: t.startswith('\x1f\x8b')),
    ('bzip2',  lambda t: t.startswith('BZh')),
    ('zlib',   lambda t: len(t) >= 2 and t[0] == 'x' and t[1] in ('\x01', '\x5e', '\x9c', '\xda')),
]


def _count_valid_domain_labels(candidate: str) -> int:
    """Return how many labels are in ``candidate`` if it's a bare domain, else 0."""
    m = re.match(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:' + _TLD_ALTERNATION + r')$',
        candidate, re.IGNORECASE,
    )
    if not m:
        return 0
    return candidate.count('.') + 1


def is_valid_domain(text: str) -> bool:
    """True iff ``text`` is (whitespace-trimmed, optional scheme/path) a valid domain
    whose final label is a known TLD and whose other labels are valid host labels.

    Regression anchors:
        ``goramli.bsmch.idf.il``       -> True   (multi-label, valid .il TLD)
        ``google.com``                 -> True
        ``WT.MH#F(L]B7KI+N2?1^NF4II``  -> False  (invalid labels, no valid TLD)
        ``xu.ni``                      -> False  (``ni`` not in TLD list; ``wt.mh``
                                                 would be rejected the same way)
    """
    return DOMAIN_PATTERN.match(text.strip()) is not None


def _looks_like_jwt(text: str) -> bool:
    """True iff ``text`` has the exact three-segment JWT shape.

    We deliberately do NOT decode the segments here (the scorer is hot; decoding
    is the decoder's job). The shape check is enough to flag a strong structural
    match, and a three-base64url-segment string is vanishingly unlikely to arise
    by accident from a noise decode.
    """
    t = text.strip()
    if not _JWT_PATTERN.match(t):
        return False
    # Each segment must look like base64url (it would otherwise match any 'a.b.c').
    seg_len_ok = all(len(seg) >= 2 for seg in t.split('.'))
    return seg_len_ok


def _looks_like_pem(text: str) -> bool:
    return bool(_PEM_PATTERN.match(text.strip()))


def _looks_like_magic(text: str) -> bool:
    return any(check(text) for _, check in _MAGIC_PATTERNS)


def get_structural_signals(text: str) -> dict:
    """Return a dict of normalized *binary* structural signals (0.0/1.0) for a
    decoded candidate.

    Signals:
        strong_structural_match: 1.0 if the candidate is a *genuinely valid* domain,
            JWT, PEM block, or known magic-bytes format. This is the scorer's
            dominant signal — setting it on gibberish is the bug we fixed, so every
            check here is anchored, not loose. 0.0 otherwise.
        valid_domain:     1.0 if a valid domain (subset of strong match, exposed for
            notes/telemetry).
        valid_jwt:        1.0 if a JWT shape.
        valid_pem:        1.0 if a PEM block.
        valid_magic:      1.0 if a recognized magic-bytes prefix.

    All values are floats in {0.0, 1.0}; the scorer can treat them uniformly.
    """
    if not text:
        return {k: 0.0 for k in (
            'strong_structural_match', 'valid_domain', 'valid_jwt',
            'valid_pem', 'valid_magic',
        )}

    t = text.strip()
    valid_domain = 1.0 if is_valid_domain(t) else 0.0
    valid_jwt = 1.0 if _looks_like_jwt(t) else 0.0
    valid_pem = 1.0 if _looks_like_pem(t) else 0.0
    valid_magic = 1.0 if _looks_like_magic(t) else 0.0

    strong = 1.0 if (valid_domain or valid_jwt or valid_pem or valid_magic) else 0.0
    return {
        'strong_structural_match': strong,
        'valid_domain': valid_domain,
        'valid_jwt': valid_jwt,
        'valid_pem': valid_pem,
        'valid_magic': valid_magic,
    }


# ── Hint detection (CLI-facing, separate from structural signals) ────────────

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

    # --- Structural Fingerprinting (mirrors get_structural_signals) ---
    signals = get_structural_signals(t)
    if signals['valid_domain']:
        hints.append("valid domain structure (labels + known TLD)")
    if signals['valid_jwt']:
        hints.append("JWT structure (header.payload.signature)")
    if signals['valid_pem']:
        hints.append("PEM/DER format (certificate/key)")
    if signals['valid_magic']:
        for name, check in _MAGIC_PATTERNS:
            if check(t):
                hints.append(f"{name.upper()} data (magic bytes)")
                break

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
        if signals['valid_jwt']:
            priority_hints.append("JWT structure (high confidence)")
        if signals['valid_pem']:
            priority_hints.append("PEM/DER format (high confidence)")
        if signals['valid_magic']:
            priority_hints.append("Binary file format (high confidence)")
        if signals['valid_domain']:
            priority_hints.append("valid domain structure (high confidence)")
        if priority_hints:
            return priority_hints

    return hints
