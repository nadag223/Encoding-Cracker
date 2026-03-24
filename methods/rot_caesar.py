"""ROT / Caesar cipher shifts: ROT1–ROT25, ROT47 (full printable), ROT5 (digits)."""

def rot_n(text: str, n: int) -> str:
    """Generic Caesar shift by n positions (letters only)."""
    result = []
    for c in text:
        if c.isupper():
            result.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        elif c.islower():
            result.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        else:
            result.append(c)
    return ''.join(result)

def rot47(text: str) -> str:
    """ROT47: rotate all printable ASCII chars (33–126) by 47."""
    result = []
    for c in text:
        o = ord(c)
        if 33 <= o <= 126:
            result.append(chr((o - 33 + 47) % 94 + 33))
        else:
            result.append(c)
    return ''.join(result)

def rot5(text: str) -> str:
    """ROT5: rotate digit characters by 5."""
    result = []
    for c in text:
        if c.isdigit():
            result.append(chr((ord(c) - ord('0') + 5) % 10 + ord('0')))
        else:
            result.append(c)
    return ''.join(result)

def get_methods():
    methods = []
    # ROT1 – ROT25
    for n in range(1, 26):
        shift = n
        methods.append((f"ROT{n}", lambda t, s=shift: rot_n(t, s)))
    methods.append(("ROT47", rot47))
    methods.append(("ROT5 (digits only)", rot5))
    return methods
