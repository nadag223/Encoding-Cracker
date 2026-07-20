import numpy as np
from typing import List, Tuple
import itertools
import re

# Constants for cipher keys and configurations
VIGENERE_KEYS = ["A", "KEY", "SECRET", "CRYPTO", "VIGENERE", "CIPHER", "ABC", "ABCD", "PASSWORD"]
AUTOKEY_KEYS = ["A", "KEY", "SECRET", "CRYPTO", "AUTOKEY", "CIPHER", "PASSWORD"]
BIFID_KEYS = ["KEYWORD", "SECRET", "CRYPTO", "BIFID", "ABCDEFGHIKLMNOPQRSTUVWXYZ"]
BIFID_PERIODS = [5, 7, 10, 15]
TRIFID_KEYS = ["KEYWORD", "SECRET", "CRYPTO", "TRIFID", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
TRIFID_PERIODS = [5, 7, 10]
FOURSQUARE_KEYS = [
    ("KEYWORD", "SECRET"),
    ("CRYPTO", "CIPHER"),
    ("FOURSQUARE", "ENCRYPT"),
    ("ABCDEFGHIKLMNOPQRSTUVWXYZ", "ABCDEFGHIKLMNOPQRSTUVWXYZ")
]
TWOSQUARE_KEYS = [
    ("KEYWORD", "SECRET"),
    ("CRYPTO", "CIPHER"),
    ("TWOSQUARE", "ENCRYPT"),
    ("ABCDEFGHIKLMNOPQRSTUVWXYZ", "ABCDEFGHIKLMNOPQRSTUVWXYZ")
]
TWOSQUARE_MODES = [True, False]  # True = vertical, False = horizontal
ADFGVX_KEYS = ["KEYWORD", "SECRET", "CRYPTO", "ADFGVX", "CIPHER"]
ADFGVX_POLYBIUS_KEYS = [
    "PHQGMEAYLNOFDXKRCVSIWBUZT",
    "KEYWORDCRYPTOABDFGHILMNQSUVWXZ"
]
HILL_KEYS_2X2 = [
    [[3, 3], [2, 5]],  # Example key
    [[9, 4], [5, 7]],  # Another example
    [[5, 17], [8, 3]]  # Another example
]

# Load running key sources
try:
    with open('wordlists/running_key_sources.txt', 'r', encoding='utf-8') as f:
        RUNNING_KEY_SOURCES = [line.strip() for line in f if line.strip()]
except:
    RUNNING_KEY_SOURCES = [
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
        "CRYPTOGRAPHYISTHEARTANDSCIENCEOFSECRETWRITING",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ]

# Enigma configurations
ENIGMA_CONFIGS = [
    {
        'rotors': ['I', 'II', 'III'],
        'reflector': 'B',
        'rings': [1, 1, 1],
        'positions': ['A', 'A', 'A'],
        'plugboard': []
    },
    {
        'rotors': ['III', 'IV', 'I'],
        'reflector': 'C',
        'rings': [1, 20, 13],
        'positions': ['X', 'Y', 'Z'],
        'plugboard': [('A', 'M'), ('F', 'I'), ('N', 'V'), ('P', 'S'), ('T', 'U')]
    }
]

def atbash_latin(text):
    """Atbash cipher for Latin alphabet"""
    result = []
    for c in text.upper():
        if 'A' <= c <= 'Z':
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else:
            result.append(c)
    return ''.join(result)

def atbash_hebrew(text):
    """Atbash cipher for Hebrew alphabet (transliterated to Latin)"""
    # Hebrew Atbash mapping (transliterated)
    hebrew_atbash = {
        'A': 'Z', 'B': 'Y', 'G': 'P', 'D': 'O', 'H': 'X', 'V': 'W',
        'Z': 'A', 'Y': 'B', 'P': 'G', 'O': 'D', 'X': 'H', 'W': 'V',
        'T': 'Q', 'K': 'L', 'L': 'K', 'M': 'N', 'N': 'M', 'S': 'E',
        'E': 'S', 'I': 'C', 'C': 'I', 'R': 'F', 'F': 'R', 'U': 'J'
    }
    result = []
    for c in text.upper():
        result.append(hebrew_atbash.get(c, c))
    return ''.join(result)

def _vigenere(text: str, key: str, decrypt: bool = True) -> str:
    """Vigenère cipher (decrypt if decrypt=True, encrypt otherwise)"""
    result = []
    key = key.upper()
    key_len = len(key)
    key_idx = 0

    for c in text.upper():
        if 'A' <= c <= 'Z':
            key_char = key[key_idx % key_len]
            key_shift = ord(key_char) - ord('A')
            if decrypt:
                shift = (ord(c) - ord('A') - key_shift) % 26
            else:
                shift = (ord(c) - ord('A') + key_shift) % 26
            result.append(chr(shift + ord('A')))
            key_idx += 1
        else:
            result.append(c)
    return ''.join(result)

def _beaufort(text: str, key: str) -> str:
    """Beaufort cipher (decryption)"""
    result = []
    key = key.upper()
    key_len = len(key)
    key_idx = 0

    for c in text.upper():
        if 'A' <= c <= 'Z':
            key_char = key[key_idx % key_len]
            key_shift = ord(key_char) - ord('A')
            shift = (key_shift - (ord(c) - ord('A'))) % 26
            result.append(chr(shift + ord('A')))
            key_idx += 1
        else:
            result.append(c)
    return ''.join(result)

def _affine_decrypt(text: str, a: int, b: int) -> str:
    """Affine cipher decryption"""
    result = []
    a_inv = pow(a, -1, 26)  # Modular inverse of a

    for c in text.upper():
        if 'A' <= c <= 'Z':
            x = ord(c) - ord('A')
            shift = (a_inv * (x - b)) % 26
            result.append(chr(shift + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def _playfair_decrypt(text: str, key: str) -> str:
    """Playfair cipher decryption"""
    # Create Playfair square
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: I/J are combined
    key = key.upper().replace("J", "I")
    key_square = ""

    # Remove duplicates from key
    seen = set()
    for c in key:
        if c in alphabet and c not in seen:
            key_square += c
            seen.add(c)

    # Add remaining alphabet letters
    for c in alphabet:
        if c not in seen:
            key_square += c

    # Create coordinate map
    coord = {}
    for i in range(5):
        for j in range(5):
            coord[key_square[i*5 + j]] = (i, j)

    # Prepare text
    text = text.upper().replace("J", "I")
    text = re.sub(r"[^A-Z]", "", text)

    # Split into digraphs
    digraphs = []
    i = 0
    while i < len(text):
        if i + 1 >= len(text):
            digraphs.append(text[i] + "X")
            i += 1
        elif text[i] == text[i+1]:
            digraphs.append(text[i] + "X")
            i += 1
        else:
            digraphs.append(text[i] + text[i+1])
            i += 2

    # Decrypt digraphs
    result = []
    for d in digraphs:
        a, b = d[0], d[1]
        row_a, col_a = coord[a]
        row_b, col_b = coord[b]

        if row_a == row_b:
            # Same row: shift left
            result.append(key_square[row_a * 5 + (col_a - 1) % 5])
            result.append(key_square[row_b * 5 + (col_b - 1) % 5])
        elif col_a == col_b:
            # Same column: shift up
            result.append(key_square[((row_a - 1) % 5) * 5 + col_a])
            result.append(key_square[((row_b - 1) % 5) * 5 + col_b])
        else:
            # Rectangle: swap columns
            result.append(key_square[row_a * 5 + col_b])
            result.append(key_square[row_b * 5 + col_a])

    return ''.join(result)

def hill_decrypt_2x2(text: str, key_matrix: List[List[int]]) -> str:
    """Hill cipher decryption with 2x2 key matrix"""
    # Calculate determinant and modular inverse
    det = key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]
    det = det % 26
    det_inv = pow(det, -1, 26)

    # Calculate adjugate matrix
    adj = [
        [key_matrix[1][1], -key_matrix[0][1]],
        [-key_matrix[1][0], key_matrix[0][0]]
    ]

    # Calculate inverse matrix
    inv_matrix = [
        [(det_inv * adj[0][0]) % 26, (det_inv * adj[0][1]) % 26],
        [(det_inv * adj[1][0]) % 26, (det_inv * adj[1][1]) % 26]
    ]

    # Prepare text
    text = re.sub(r"[^A-Z]", "", text.upper())
    if len(text) % 2 != 0:
        text += "X"

    # Decrypt
    result = []
    for i in range(0, len(text), 2):
        vec = [ord(text[i]) - ord('A'), ord(text[i+1]) - ord('A')]
        decrypted = [
            (inv_matrix[0][0] * vec[0] + inv_matrix[0][1] * vec[1]) % 26,
            (inv_matrix[1][0] * vec[0] + inv_matrix[1][1] * vec[1]) % 26
        ]
        result.append(chr(decrypted[0] + ord('A')))
        result.append(chr(decrypted[1] + ord('A')))

    return ''.join(result)

def autokey_decrypt(text: str, key: str) -> str:
    """Autokey cipher decryption"""
    result = []
    key = key.upper()
    key_idx = 0

    for c in text.upper():
        if 'A' <= c <= 'Z':
            if key_idx < len(key):
                # Use key character
                key_char = key[key_idx]
            else:
                # Use decrypted result as key
                key_char = result[key_idx - len(key)]

            key_shift = ord(key_char) - ord('A')
            shift = (ord(c) - ord('A') - key_shift) % 26
            result.append(chr(shift + ord('A')))
            key_idx += 1
        else:
            result.append(c)

    return ''.join(result)

def bifid_decrypt(text: str, key: str, period: int) -> str:
    """Bifid cipher decryption"""
    # Create Polybius square
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: I/J are combined
    key = key.upper().replace("J", "I")
    key_square = ""

    # Remove duplicates from key
    seen = set()
    for c in key:
        if c in alphabet and c not in seen:
            key_square += c
            seen.add(c)

    # Add remaining alphabet letters
    for c in alphabet:
        if c not in seen:
            key_square += c

    # Create coordinate map
    coord = {}
    for i in range(5):
        for j in range(5):
            coord[key_square[i*5 + j]] = (i, j)

    # Prepare text
    text = text.upper().replace("J", "I")
    text = re.sub(r"[^A-Z]", "", text)

    # Split into periods
    blocks = [text[i:i+period] for i in range(0, len(text), period)]

    result = []
    for block in blocks:
        # Get coordinates
        coords = []
        for c in block:
            if c in coord:
                coords.append(coord[c])

        # Flatten coordinates
        flat_coords = []
        for row, col in coords:
            flat_coords.append(row)
            flat_coords.append(col)

        # Reconstruct digraphs
        for i in range(0, len(flat_coords), 2):
            if i + 1 < len(flat_coords):
                row = flat_coords[i]
                col = flat_coords[i+1]
                result.append(key_square[row * 5 + col])

    return ''.join(result)

def trifid_decrypt(text: str, key: str, period: int) -> str:
    """Trifid cipher decryption"""
    # Create Trifid cube
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()
    key_cube = ""

    # Remove duplicates from key
    seen = set()
    for c in key:
        if c in alphabet and c not in seen:
            key_cube += c
            seen.add(c)

    # Add remaining alphabet letters
    for c in alphabet:
        if c not in seen:
            key_cube += c

    # Create coordinate map
    coord = {}
    for i in range(3):
        for j in range(3):
            for k in range(3):
                idx = i * 9 + j * 3 + k
                if idx < len(key_cube):
                    coord[key_cube[idx]] = (i, j, k)

    # Prepare text
    text = re.sub(r"[^A-Z]", "", text.upper())

    # Split into periods
    blocks = [text[i:i+period] for i in range(0, len(text), period)]

    result = []
    for block in blocks:
        # Get coordinates
        coords = []
        for c in block:
            if c in coord:
                coords.append(coord[c])

        # Flatten coordinates
        flat_coords = []
        for i, j, k in coords:
            flat_coords.append(i)
            flat_coords.append(j)
            flat_coords.append(k)

        # Reconstruct trigraphs
        for i in range(0, len(flat_coords), 3):
            if i + 2 < len(flat_coords):
                i1 = flat_coords[i]
                i2 = flat_coords[i+1]
                i3 = flat_coords[i+2]
                idx = i1 * 9 + i2 * 3 + i3
                if idx < len(key_cube):
                    result.append(key_cube[idx])

    return ''.join(result)

def foursquare_decrypt(text: str, key1: str, key2: str) -> str:
    """Four-square cipher decryption"""
    # Create two Polybius squares
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: I/J are combined

    def create_square(key):
        key = key.upper().replace("J", "I")
        square = ""
        seen = set()
        for c in key:
            if c in alphabet and c not in seen:
                square += c
                seen.add(c)
        for c in alphabet:
            if c not in seen:
                square += c
        return square

    square1 = create_square(key1)
    square2 = create_square(key2)

    # Create coordinate maps
    coord1 = {}
    coord2 = {}
    for i in range(5):
        for j in range(5):
            coord1[square1[i*5 + j]] = (i, j)
            coord2[square2[i*5 + j]] = (i, j)

    # Prepare text
    text = text.upper().replace("J", "I")
    text = re.sub(r"[^A-Z]", "", text)
    if len(text) % 2 != 0:
        text += "X"

    # Decrypt digraphs
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        if a in coord1 and b in coord2:
            row_a, col_a = coord1[a]
            row_b, col_b = coord2[b]
            # Use standard alphabet square for the other two corners
            result.append(alphabet[row_a * 5 + col_b])
            result.append(alphabet[row_b * 5 + col_a])

    return ''.join(result)

def twosquare_decrypt(text: str, key1: str, key2: str, vertical: bool = True) -> str:
    """Two-square cipher decryption"""
    # Create two Polybius squares
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: I/J are combined

    def create_square(key):
        key = key.upper().replace("J", "I")
        square = ""
        seen = set()
        for c in key:
            if c in alphabet and c not in seen:
                square += c
                seen.add(c)
        for c in alphabet:
            if c not in seen:
                square += c
        return square

    square1 = create_square(key1)
    square2 = create_square(key2)

    # Create coordinate maps
    coord1 = {}
    coord2 = {}
    for i in range(5):
        for j in range(5):
            coord1[square1[i*5 + j]] = (i, j)
            coord2[square2[i*5 + j]] = (i, j)

    # Prepare text
    text = text.upper().replace("J", "I")
    text = re.sub(r"[^A-Z]", "", text)
    if len(text) % 2 != 0:
        text += "X"

    # Decrypt digraphs
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        if a in coord1 and b in coord2:
            row_a, col_a = coord1[a]
            row_b, col_b = coord2[b]

            if vertical:
                # Vertical two-square: same column
                result.append(square1[row_a * 5 + col_b])
                result.append(square2[row_b * 5 + col_a])
            else:
                # Horizontal two-square: same row
                result.append(square1[row_b * 5 + col_a])
                result.append(square2[row_a * 5 + col_b])

    return ''.join(result)

def adfgvx_decrypt(text: str, key: str, polybius_key: str) -> str:
    """ADFGVX cipher decryption"""
    # Create Polybius square
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    polybius_key = polybius_key.upper()

    # Create square
    square = ""
    seen = set()
    for c in polybius_key:
        if c in alphabet and c not in seen:
            square += c
            seen.add(c)
    for c in alphabet:
        if c not in seen:
            square += c

    # Create coordinate map
    coord = {}
    for i in range(6):
        for j in range(6):
            coord[square[i*6 + j]] = (i, j)

    # ADFGVX headers
    headers = "ADFGVX"
    header_coord = {}
    for i, h in enumerate(headers):
        header_coord[h] = i

    # Prepare text
    text = text.upper()
    text = re.sub(r"[^ADFGVX]", "", text)

    # Transposition step
    key = key.upper()
    key_order = sorted(range(len(key)), key=lambda k: key[k])

    # Determine column count
    col_count = len(key)
    row_count = len(text) // col_count
    if len(text) % col_count != 0:
        row_count += 1

    # Create transposition grid
    grid = [[''] * col_count for _ in range(row_count)]
    idx = 0
    for col in key_order:
        for row in range(row_count):
            if idx < len(text):
                grid[row][col] = text[idx]
                idx += 1

    # Read grid by rows
    transposed = ""
    for row in range(row_count):
        for col in range(col_count):
            if grid[row][col]:
                transposed += grid[row][col]

    # Convert back to digraphs
    digraphs = [transposed[i:i+2] for i in range(0, len(transposed), 2)]

    # Decrypt digraphs
    result = []
    for d in digraphs:
        if len(d) == 2 and d[0] in header_coord and d[1] in header_coord:
            row = header_coord[d[0]]
            col = header_coord[d[1]]
            result.append(square[row * 6 + col])

    return ''.join(result)

def adfgx_decrypt(text: str, key: str, polybius_key: str) -> str:
    """ADFGX cipher decryption"""
    # Create Polybius square
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: I/J are combined
    polybius_key = polybius_key.upper().replace("J", "I")

    # Create square
    square = ""
    seen = set()
    for c in polybius_key:
        if c in alphabet and c not in seen:
            square += c
            seen.add(c)
    for c in alphabet:
        if c not in seen:
            square += c

    # Create coordinate map
    coord = {}
    for i in range(5):
        for j in range(5):
            coord[square[i*5 + j]] = (i, j)

    # ADFGX headers
    headers = "ADFGX"
    header_coord = {}
    for i, h in enumerate(headers):
        header_coord[h] = i

    # Prepare text
    text = text.upper()
    text = re.sub(r"[^ADFGX]", "", text)

    # Transposition step
    key = key.upper()
    key_order = sorted(range(len(key)), key=lambda k: key[k])

    # Determine column count
    col_count = len(key)
    row_count = len(text) // col_count
    if len(text) % col_count != 0:
        row_count += 1

    # Create transposition grid
    grid = [[''] * col_count for _ in range(row_count)]
    idx = 0
    for col in key_order:
        for row in range(row_count):
            if idx < len(text):
                grid[row][col] = text[idx]
                idx += 1

    # Read grid by rows
    transposed = ""
    for row in range(row_count):
        for col in range(col_count):
            if grid[row][col]:
                transposed += grid[row][col]

    # Convert back to digraphs
    digraphs = [transposed[i:i+2] for i in range(0, len(transposed), 2)]

    # Decrypt digraphs
    result = []
    for d in digraphs:
        if len(d) == 2 and d[0] in header_coord and d[1] in header_coord:
            row = header_coord[d[0]]
            col = header_coord[d[1]]
            result.append(square[row * 5 + col])

    return ''.join(result)

def running_key_decrypt(text: str, running_key: str) -> str:
    """Running key cipher decryption"""
    result = []
    running_key = running_key.upper()
    key_idx = 0

    for c in text.upper():
        if 'A' <= c <= 'Z':
            if key_idx < len(running_key):
                key_char = running_key[key_idx]
            else:
                # If running key is exhausted, wrap around
                key_char = running_key[key_idx % len(running_key)]

            key_shift = ord(key_char) - ord('A')
            shift = (ord(c) - ord('A') - key_shift) % 26
            result.append(chr(shift + ord('A')))
            key_idx += 1
        else:
            result.append(c)

    return ''.join(result)

def _enigma_process(text: str, rotors: List[str], reflector: str, rings: List[int], positions: List[str], plugboard: List[Tuple[str, str]]) -> str:
    """Simplified Enigma machine processing"""
    try:
        from py_enigma import Enigma, Rotor, Reflector
    except ImportError:
        # Fallback simple implementation
        result = []
        for i, c in enumerate(text.upper()):
            if 'A' <= c <= 'Z':
                # Simple Caesar shift as fallback
                shift = (ord(c) - ord('A') + i) % 26
                result.append(chr(shift + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    # Create Enigma machine
    rotor_objects = []
    for i, rotor_name in enumerate(rotors):
        rotor_objects.append(Rotor(rotor_name, rings[i], positions[i]))

    reflector_obj = Reflector(reflector)

    enigma = Enigma(rotor_objects, reflector_obj, plugboard)

    return enigma.encipher(text)

def bacon_ab_decode(text: str) -> str:
    """Bacon cipher decode (A/B variant)"""
    # Remove non-alphabetic characters and convert to uppercase
    cleaned = re.sub(r"[^A-Za-z]", "", text).upper()

    # Convert A/B to binary
    binary = ""
    for c in cleaned:
        if c == 'A':
            binary += '0'
        elif c == 'B':
            binary += '1'
        else:
            # Treat other letters as A (0) for robustness
            binary += '0'

    # Pad to multiple of 5
    while len(binary) % 5 != 0:
        binary += '0'

    # Decode 5-bit chunks
    result = []
    for i in range(0, len(binary), 5):
        chunk = binary[i:i+5]
        if len(chunk) == 5:
            num = int(chunk, 2)
            if 0 <= num < 26:
                result.append(chr(num + ord('A')))

    return ''.join(result)

def bacon_01_decode(text: str) -> str:
    """Bacon cipher decode (0/1 variant)"""
    # Remove non-0/1 characters
    cleaned = re.sub(r"[^01]", "", text)

    # Pad to multiple of 5
    while len(cleaned) % 5 != 0:
        cleaned += '0'

    # Decode 5-bit chunks
    result = []
    for i in range(0, len(cleaned), 5):
        chunk = cleaned[i:i+5]
        if len(chunk) == 5:
            num = int(chunk, 2)
            if 0 <= num < 26:
                result.append(chr(num + ord('A')))

    return ''.join(result)

def polybius_decode(text: str) -> str:
    """Polybius square decode"""
    # Standard Polybius square (I/J combined)
    square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    # Extract coordinates (numbers only)
    coords = re.sub(r"[^0-9]", "", text)

    # Decode pairs
    result = []
    for i in range(0, len(coords), 2):
        if i + 1 < len(coords):
            row = int(coords[i]) - 1
            col = int(coords[i+1]) - 1
            if 0 <= row < 5 and 0 <= col < 5:
                result.append(square[row * 5 + col])

    return ''.join(result)

def tap_decode(text: str) -> str:
    """Tap code decode"""
    # Tap code square (I/J combined)
    square = [
        ['A', 'B', 'C', 'D', 'E'],
        ['F', 'G', 'H', 'I', 'K'],
        ['L', 'M', 'N', 'O', 'P'],
        ['Q', 'R', 'S', 'T', 'U'],
        ['V', 'W', 'X', 'Y', 'Z']
    ]

    # Extract numbers
    numbers = re.findall(r"\d+", text)

    # Decode pairs
    result = []
    for i in range(0, len(numbers), 2):
        if i + 1 < len(numbers):
            row = int(numbers[i]) - 1
            col = int(numbers[i+1]) - 1
            if 0 <= row < 5 and 0 <= col < 5:
                result.append(square[row][col])

    return ''.join(result)

def get_methods():
    methods = []

    methods.append(("Atbash Latin", atbash_latin))
    methods.append(("Atbash Hebrew (transliterated)", atbash_hebrew))

    # Import helper functions from cracker.py to avoid lambda pickling
    from cracker import (
        _make_vigenere_fn, _make_beaufort_fn, _make_affine_fn, _make_playfair_fn,
        _make_hill_fn, _make_autokey_fn, _make_bifid_fn, _make_trifid_fn,
        _make_foursquare_fn, _make_twosquare_fn, _make_adfgvx_fn, _make_adfgx_fn,
        _make_running_key_fn, _make_enigma_fn
    )

    for k in VIGENERE_KEYS:
        methods.append((f"Vigenere key={k}", _make_vigenere_fn(k)))

    for k in VIGENERE_KEYS:
        methods.append((f"Beaufort key={k}", _make_beaufort_fn(k)))

    # Affine: all valid a values (coprime to 26)
    for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
        for b in range(0, 26, 5):
            methods.append((f"Affine a={a} b={b}", _make_affine_fn(a, b)))

    methods.append(("Bacon A/B Decode", bacon_ab_decode))
    methods.append(("Bacon 0/1 Decode", bacon_01_decode))
    methods.append(("Polybius Square Decode", polybius_decode))
    methods.append(("Tap Code Decode", tap_decode))

    for k in ["playfair","keyword","secret"]:
        methods.append((f"Playfair key={k}", _make_playfair_fn(k)))

    # Hill Cipher
    for km in HILL_KEYS_2X2:
        methods.append((f"Hill 2x2 key={km}", _make_hill_fn(km)))

    # Autokey Cipher
    for k in AUTOKEY_KEYS:
        methods.append((f"Autokey key={k}", _make_autokey_fn(k)))

    # Bifid Cipher
    for k in BIFID_KEYS:
        for p in BIFID_PERIODS:
            methods.append((f"Bifid key={k} period={p}", _make_bifid_fn(k, p)))

    # Trifid Cipher
    for k in TRIFID_KEYS:
        for p in TRIFID_PERIODS:
            methods.append((f"Trifid key={k} period={p}", _make_trifid_fn(k, p)))

    # Four-Square Cipher
    for k1, k2 in FOURSQUARE_KEYS:
        methods.append((f"Four-Square key1={k1} key2={k2}", _make_foursquare_fn(k1, k2)))

    # Two-Square Cipher
    for k1, k2 in TWOSQUARE_KEYS:
        for v in TWOSQUARE_MODES:
            mode_str = "vertical" if v else "horizontal"
            methods.append((f"Two-Square {mode_str} key1={k1} key2={k2}", _make_twosquare_fn(k1, k2, v)))

    # ADFGVX
    for k in ADFGVX_KEYS:
        for pk in ADFGVX_POLYBIUS_KEYS:
            methods.append((f"ADFGVX key={k} polybius={pk}", _make_adfgvx_fn(k, pk)))

    # ADFGX
    for k in ADFGVX_KEYS:
        for pk in ["PHQGMEAYLNOFDXKRCVSZWIBUT", "KEYWORD"]:
            methods.append((f"ADFGX key={k} polybius={pk}", _make_adfgx_fn(k, pk)))

    # Running Key Cipher
    for i, rk in enumerate(RUNNING_KEY_SOURCES[:5]):  # limit to first 5 to avoid explosion
        methods.append((f"Running Key source#{i+1}", _make_running_key_fn(rk)))

    # Enigma Simulator
    for i, cfg in enumerate(ENIGMA_CONFIGS):
        methods.append((f"Enigma config#{i+1} rotors={cfg['rotors']} refl={cfg['reflector']}", _make_enigma_fn(cfg)))

    return methods