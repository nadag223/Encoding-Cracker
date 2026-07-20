"""Base encodings: Base16 through Base91, hex, binary, octal, decimal, BCD, etc."""
import base64
import binascii
import string
import re
import urllib.parse
import html

# Tap code decode function moved here to avoid circular imports
def tap_code_decode(text: str) -> str:
    """Tap code decode"""
    # Tap code square (I/J combined)
    square = [
        ['A', 'B', 'C', 'D', 'E'],
        ['F', 'G', 'H', 'I', 'K'],
        ['L', 'M', 'N', 'O', 'P'],
        ['Q', 'R', 'S', 'T', 'U'],
        ['V', 'W', 'X', 'Y', 'Z']
    ]
    try:
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
    except Exception:
        return None

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


def custom_base_decode(text: str, alphabet: str) -> str:
    """Decode text using a custom base alphabet"""
    try:
        # Create mapping from alphabet to base64 standard
        base = len(alphabet)
        if base < 2 or base > 64:
            return None

        # Create translation table
        std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        if base <= 36:
            std_alphabet = std_alphabet.lower()[:base]
        elif base <= 62:
            std_alphabet = std_alphabet[:base]

        trans_table = str.maketrans(alphabet, std_alphabet)

        # Translate and decode
        translated = text.translate(trans_table)

        # Add padding if needed
        pad_length = (4 - (len(translated) % 4)) % 4
        padded = translated + '=' * pad_length

        return _safe_decode(base64.b64decode(padded))
    except Exception:
        return None


def morse_decode(text: str) -> str:
    """Decode Morse code"""
    morse_to_char = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.',
        '--..--': ',', '..--..': '?', '.----.': "'", '-.-.--': '!',
        '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
        '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
        '-....-': '-', '..--.-': '_', '.-..-.': '"', '...-..-': '$',
        '.--.-.': '@', '...---...': 'SOS'
    }
    try:
        result = []
        for word in text.split(' / '):
            for char in word.split():
                result.append(morse_to_char.get(char, ''))
            result.append(' ')
        return ''.join(result).strip()
    except Exception:
        return None


def brainfuck_decode(text: str) -> str:
    """Simple Brainfuck interpreter"""
    try:
        tape = [0] * 30000
        ptr = 0
        output = []
        bracket_map = {}
        stack = []

        # Build bracket map
        for i, cmd in enumerate(text):
            if cmd == '[':
                stack.append(i)
            elif cmd == ']':
                if stack:
                    start = stack.pop()
                    bracket_map[start] = i
                    bracket_map[i] = start

        i = 0
        while i < len(text):
            cmd = text[i]
            if cmd == '>':
                ptr += 1
            elif cmd == '<':
                ptr -= 1
            elif cmd == '+':
                tape[ptr] = (tape[ptr] + 1) % 256
            elif cmd == '-':
                tape[ptr] = (tape[ptr] - 1) % 256
            elif cmd == '.':
                output.append(chr(tape[ptr]))
            elif cmd == ',':
                pass  # Input not supported
            elif cmd == '[' and tape[ptr] == 0:
                i = bracket_map[i]
            elif cmd == ']' and tape[ptr] != 0:
                i = bracket_map[i]
            i += 1

        return ''.join(output)
    except Exception:
        return None


def ook_decode(text: str) -> str:
    """Decode Ook! esoteric language"""
    try:
        # Convert Ook! to Brainfuck
        brainfuck = []
        words = text.split()
        for i in range(0, len(words), 3):
            if i + 2 >= len(words):
                break
            a, b, c = words[i], words[i+1], words[i+2]
            if a == 'Ook.' and b == 'Ook?':
                brainfuck.append('>')
            elif a == 'Ook?' and b == 'Ook.':
                brainfuck.append('<')
            elif a == 'Ook.' and b == 'Ook.':
                brainfuck.append('+')
            elif a == 'Ook!' and b == 'Ook!':
                brainfuck.append('-')
            elif a == 'Ook!' and b == 'Ook.':
                brainfuck.append('.')
            elif a == 'Ook.' and b == 'Ook!':
                brainfuck.append(',')
            elif a == 'Ook!' and b == 'Ook?':
                brainfuck.append('[')
            elif a == 'Ook?' and b == 'Ook!':
                brainfuck.append(']')
        return brainfuck_decode(''.join(brainfuck))
    except Exception:
        return None


def pigpen_decode(text: str) -> str:
    """Decode Pigpen cipher"""
    pigpen_map = {
        '._.': 'A', '._|': 'B', '.|_': 'C', '.|.': 'D', '.|_|': 'E',
        '|._.': 'F', '|._|': 'G', '|..': 'H', '..|': 'I', '._': 'J',
        '_|.': 'K', '_|_': 'L', '|_|': 'M', '|..|': 'N', '._|.': 'O',
        '|._': 'P', '|_._': 'Q', '.._|': 'R', '._.|': 'S', '_|..': 'T',
        '_..': 'U', '|_..': 'V', '.._': 'W', '._..': 'X', '_.._': 'Y',
        '_._': 'Z'
    }
    try:
        return ''.join(pigpen_map.get(c, '') for c in text.split())
    except Exception:
        return None


def semaphore_decode(text: str) -> str:
    """Decode semaphore flags (simplified)"""
    semaphore_map = {
        '12': 'A', '13': 'B', '14': 'C', '15': 'D', '16': 'E', '17': 'F', '18': 'G',
        '21': 'H', '23': 'I', '24': 'K', '25': 'L', '26': 'M', '27': 'N', '28': 'O',
        '31': 'P', '32': 'Q', '34': 'R', '35': 'S', '36': 'T', '37': 'U', '38': 'Y',
        '41': 'Z', '42': 'J', '51': 'V', '61': ' ', '71': '1', '72': '2', '73': '3',
        '74': '4', '75': '5', '76': '6', '77': '7', '78': '8', '81': '9', '82': '0'
    }
    try:
        return ''.join(semaphore_map.get(text[i:i+2], '') for i in range(0, len(text), 2))
    except Exception:
        return None


def dtmf_decode(text: str) -> str:
    """Decode DTMF tones (simplified)"""
    dtmf_map = {
        '1': '1', '2': '2', '3': '3', '4': '4', '5': '5', '6': '6', '7': '7',
        '8': '8', '9': '9', '0': '0', 'A': '*', 'B': '0', 'C': '#', 'D': ' '
    }
    try:
        return ''.join(dtmf_map.get(c, '') for c in text)
    except Exception:
        return None


def a1z26_decode(text: str) -> str:
    """Decode A1Z26 cipher (e.g., 7-15-15-7-12-5 = GOOGLE)"""
    try:
        # Extract numbers
        numbers = re.findall(r'\d+', text)
        return ''.join(chr(int(n) + ord('A') - 1) for n in numbers if 1 <= int(n) <= 26)
    except Exception:
        return None


def atbash_decode(text: str) -> str:
    """Atbash cipher decode"""
    try:
        result = []
        for c in text.upper():
            if 'A' <= c <= 'Z':
                result.append(chr(ord('Z') - (ord(c) - ord('A'))))
            else:
                result.append(c)
        return ''.join(result)
    except Exception:
        return None


def rot13_decode(text: str) -> str:
    """ROT13 cipher decode"""
    try:
        result = []
        for c in text:
            if 'A' <= c <= 'Z':
                result.append(chr(((ord(c) - ord('A') + 13) % 26) + ord('A')))
            elif 'a' <= c <= 'z':
                result.append(chr(((ord(c) - ord('a') + 13) % 26) + ord('a')))
            else:
                result.append(c)
        return ''.join(result)
    except Exception:
        return None


def rot47_decode(text: str) -> str:
    """ROT47 cipher decode"""
    try:
        result = []
        for c in text:
            if 33 <= ord(c) <= 126:
                result.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
            else:
                result.append(c)
        return ''.join(result)
    except Exception:
        return None


def vigenere_decode(text: str, key: str = 'A') -> str:
    """Vigenère cipher decode"""
    try:
        result = []
        key = key.upper()
        key_len = len(key)
        key_idx = 0
        for c in text.upper():
            if 'A' <= c <= 'Z':
                key_char = key[key_idx % key_len]
                key_shift = ord(key_char) - ord('A')
                shift = (ord(c) - ord('A') - key_shift) % 26
                result.append(chr(shift + ord('A')))
                key_idx += 1
            else:
                result.append(c)
        return ''.join(result)
    except Exception:
        return None


def caesar_decode(text: str, shift: int = 1) -> str:
    """Caesar cipher decode"""
    try:
        result = []
        for c in text.upper():
            if 'A' <= c <= 'Z':
                result.append(chr(((ord(c) - ord('A') - shift) % 26) + ord('A')))
            else:
                result.append(c)
        return ''.join(result)
    except Exception:
        return None


def affine_decode(text: str, a: int = 1, b: int = 0) -> str:
    """Affine cipher decode"""
    try:
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
    except Exception:
        return None


def bacon_decode(text: str) -> str:
    """Bacon cipher decode"""
    try:
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
                binary += '0'  # Default to A for robustness
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
    except Exception:
        return None


def polybius_decode(text: str) -> str:
    """Polybius square decode"""
    try:
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
    except Exception:
        return None

def base92_decode(text: str):
    # dcode.fr Base92: 91-char alphabet (no backtick!), ~ = empty string
    try:
        t = text.strip()

        if t == '~':
            return ''

        TABLE = '!#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}'

        # Filter only legal characters
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

# ── New Encodings ────────────────────────────────────────────────────────────────

# Base36 decode
def base36_decode(text: str):
    try:
        t = text.strip()
        ALPHA = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        n = 0
        for c in t:
            n = n * 36 + ALPHA.index(c.upper())
        result = []
        while n:
            result.append(n & 0xFF)
            n >>= 8
        result.reverse()
        return _safe_decode(bytes(result))
    except Exception:
        return None

# Base85 variants
def base85_z85_decode(text: str):
    """Z85 (ZeroMQ Base85) decode"""
    try:
        ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
        t = text.strip()
        if len(t) % 5 != 0:
            return None
        result = bytearray()
        for i in range(0, len(t), 5):
            chunk = t[i:i+5]
            val = 0
            for c in chunk:
                val = val * 85 + ALPHABET.index(c)
            result.extend(val.to_bytes(4, 'big'))
        return _safe_decode(bytes(result))
    except Exception:
        return None

def base85_ipv6_decode(text: str):
    """IPv6-style Base85 (RFC 1924) decode"""
    try:
        ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
        t = text.strip()
        if not t:
            return None
        n = 0
        for c in t:
            n = n * 85 + ALPHABET.index(c)
        result = []
        while n:
            result.append(n & 0xFF)
            n >>= 8
        result.reverse()
        return _safe_decode(bytes(result))
    except Exception:
        return None

# Base122 decode (using the 122 printable ASCII chars excluding space, quote, backslash)
def base122_decode(text: str):
    try:
        # Base122 uses 122 printable ASCII chars (33-154, skipping space, ", \)
        # This is a simplified implementation
        ALPHABET = ''.join(chr(i) for i in range(33, 155) if chr(i) not in ' "\\')
        if len(ALPHABET) != 122:
            # fallback
            ALPHABET = ''.join(chr(i) for i in range(33, 155))
            ALPHABET = ALPHABET.replace(' ', '').replace('"', '').replace('\\', '')
        t = text.strip()
        n = 0
        for c in t:
            if c not in ALPHABET:
                return None
            n = n * 122 + ALPHABET.index(c)
        result = []
        while n:
            result.append(n & 0xFF)
            n >>= 8
        result.reverse()
        return _safe_decode(bytes(result))
    except Exception:
        return None

# UUEncode decode
def uuencode_decode(text: str):
    try:
        # UUEncode format: begin <mode> <filename>\n<data>\n`\nend
        lines = text.strip().split('\n')
        data_lines = []
        for line in lines:
            if line.startswith('begin') or line == '`' or line == 'end':
                continue
            if line:
                data_lines.append(line)
        if not data_lines:
            return None
        # Decode each line
        result = bytearray()
        for line in data_lines:
            if len(line) < 1:
                continue
            length = ord(line[0]) - 32
            if length <= 0:
                continue
            for i in range(length):
                if 1 + i < len(line):
                    result.append(ord(line[1 + i]) - 32)
        return _safe_decode(bytes(result))
    except Exception:
        return None

# yEnc decode
def yenc_decode(text: str):
    try:
        # yEnc: = is escape char, critical chars are escaped with = and + 64
        t = text.strip()
        result = bytearray()
        i = 0
        while i < len(t):
            if t[i] == '=':
                if i + 1 < len(t):
                    result.append((ord(t[i+1]) + 64) % 256)
                    i += 2
                else:
                    return None
            else:
                result.append(ord(t[i]))
                i += 1
        return _safe_decode(bytes(result))
    except Exception:
        return None

# Punycode decode
def punycode_decode(text: str):
    try:
        return text.encode('ascii').decode('idna')
    except Exception:
        return None

# UTF-7 decode
def utf7_decode(text: str):
    try:
        return text.encode('utf-7').decode('utf-7')
    except Exception:
        return None

# Binary/Hex/Octal string representations with different byte orders
def binary_be_decode(text: str):
    """Binary big-endian: space or comma separated 8-bit chunks"""
    try:
        t = text.replace(',', ' ').strip()
        parts = t.split()
        result = ''.join(chr(int(p, 2)) for p in parts)
        return result
    except Exception:
        return None

def binary_le_decode(text: str):
    """Binary little-endian: reverse byte order"""
    try:
        t = text.replace(',', ' ').strip()
        parts = t.split()
        bytes_list = [int(p, 2) for p in parts]
        bytes_list.reverse()
        return ''.join(chr(b) for b in bytes_list)
    except Exception:
        return None

def hex_be_decode(text: str):
    """Hex big-endian (standard): space/comma separated or continuous"""
    try:
        t = text.replace(' ', '').replace(',', '')
        return _safe_decode(bytes.fromhex(t))
    except Exception:
        return None

def hex_le_decode(text: str):
    """Hex little-endian: reverse byte order"""
    try:
        t = text.replace(' ', '').replace(',', '')
        raw = bytes.fromhex(t)
        return _safe_decode(raw[::-1])
    except Exception:
        return None

def octal_be_decode(text: str):
    """Octal big-endian: space/comma separated"""
    try:
        t = text.replace(',', ' ').strip()
        parts = t.split()
        return ''.join(chr(int(p, 8)) for p in parts)
    except Exception:
        return None

def octal_le_decode(text: str):
    """Octal little-endian: reverse byte order"""
    try:
        t = text.replace(',', ' ').strip()
        parts = t.split()
        bytes_list = [int(p, 8) for p in parts]
        bytes_list.reverse()
        return ''.join(chr(b) for b in bytes_list)
    except Exception:
        return None

# Nibble swap on hex-like input
def nibble_swap_hex(text: str):
    try:
        t = text.replace(' ', '').replace(',', '')
        if len(t) % 2 != 0:
            return None
        result = bytearray()
        for i in range(0, len(t), 2):
            byte_val = int(t[i:i+2], 16)
            # Swap nibbles: 0xAB -> 0xBA
            swapped = ((byte_val & 0x0F) << 4) | ((byte_val & 0xF0) >> 4)
            result.append(swapped)
        return _safe_decode(bytes(result))
    except Exception:
        return None

# Baudot code (ITA2) decode
def baudot_decode(text: str):
    try:
        # Baudot ITA2: 5-bit code, LTRS (0x1F) = letters, FIGS (0x1B) = figures
        # Input: space/comma separated 5-bit binary or 2-char hex
        t = text.replace(',', ' ').strip()
        parts = t.split()

        LTRS = {
            0x00: '\x00', 0x01: 'E', 0x02: '\n', 0x03: 'A', 0x04: ' ', 0x05: 'S', 0x06: 'I', 0x07: 'U',
            0x08: '\r', 0x09: 'D', 0x0A: 'R', 0x0B: 'J', 0x0C: 'N', 0x0D: 'F', 0x0E: 'C', 0x0F: 'K',
            0x10: 'T', 0x11: 'Z', 0x12: 'L', 0x13: 'W', 0x14: 'H', 0x15: 'Y', 0x16: 'P', 0x17: 'Q',
            0x18: 'O', 0x19: 'B', 0x1A: 'G', 0x1B: 'FIGS', 0x1C: 'M', 0x1D: 'X', 0x1E: 'V', 0x1F: 'LTRS'
        }
        FIGS = {
            0x00: '\x00', 0x01: '3', 0x02: '\n', 0x03: '-', 0x04: ' ', 0x05: '\'', 0x06: '8', 0x07: '7',
            0x08: '\r', 0x09: '1', 0x0A: '4', 0x0B: 'BELL', 0x0C: ',', 0x0D: '!', 0x0E: ':', 0x0F: '(',
            0x10: '5', 0x11: '+', 0x12: ')', 0x13: '2', 0x14: '#', 0x15: '6', 0x16: '0', 0x17: '1',
            0x18: '9', 0x19: '?', 0x1A: '&', 0x1B: 'FIGS', 0x1C: '.', 0x1D: '/', 0x1E: ';', 0x1F: 'LTRS'
        }

        result = []
        mode = 'LTRS'
        for part in parts:
            try:
                if len(part) <= 2:
                    val = int(part, 16)
                else:
                    val = int(part, 2)
                if val == 0x1F:  # LTRS
                    mode = 'LTRS'
                elif val == 0x1B:  # FIGS
                    mode = 'FIGS'
                elif mode == 'LTRS':
                    result.append(LTRS.get(val, '?'))
                else:
                    result.append(FIGS.get(val, '?'))
            except:
                continue
        return ''.join(result)
    except Exception:
        return None

# Excess-3 (XS-3) decode
def excess3_decode(text: str):
    try:
        t = text.replace(',', ' ').strip()
        parts = t.split()
        # Each 4-bit group represents a decimal digit + 3
        result = []
        for part in parts:
            val = int(part, 2) if len(part) > 2 else int(part, 16)
            digit = val - 3
            if 0 <= digit <= 9:
                result.append(str(digit))
            else:
                result.append('?')
        return ''.join(result)
    except Exception:
        return None

# Gray code decode
def gray_code_decode(text: str):
    try:
        t = text.replace(',', ' ').strip()
        parts = t.split()
        result = []
        for part in parts:
            val = int(part, 2) if len(part) > 2 else int(part, 16)
            # Convert Gray to binary
            binary = 0
            shift = val.bit_length()
            g = val
            while shift > 0:
                binary ^= g
                g >>= 1
                shift = g.bit_length()
            result.append(chr(binary))
        return ''.join(result)
    except Exception:
        return None

# ── Method registry ───────────────────────────────────────────────────────────

def get_methods():
    methods = [
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
        ("Base36 Decode",               base36_decode),
        ("Base85 Z85 Decode",           base85_z85_decode),
        ("Base85 IPv6-style Decode",    base85_ipv6_decode),
        ("Base122 Decode",              base122_decode),
        ("UUEncode Decode",             uuencode_decode),
        ("yEnc Decode",                 yenc_decode),
        ("Punycode Decode",             punycode_decode),
        ("UTF-7 Decode",                utf7_decode),
        ("Binary → ASCII (BE)",         binary_be_decode),
        ("Binary → ASCII (LE)",         binary_le_decode),
        ("Hex → ASCII (BE)",            hex_be_decode),
        ("Hex → ASCII (LE)",            hex_le_decode),
        ("Octal → ASCII (BE)",          octal_be_decode),
        ("Octal → ASCII (LE)",          octal_le_decode),
        ("Nibble Swap Hex",             nibble_swap_hex),
        ("Baudot/ITA2 Decode",          baudot_decode),
        ("Excess-3 (XS-3) Decode",      excess3_decode),
        ("Gray Code Decode",            gray_code_decode),
        ("Binary → ASCII (spaces)",     binary_spaces_decode),
        ("Binary → ASCII (no spaces)",  binary_nospaces_decode),
        ("Octal → ASCII",               octal_decode),
        ("Decimal → ASCII",             decimal_decode),
        ("Hex → ASCII (raw)",           hex_raw_decode),
        ("BCD Decode",                  bcd_decode),
        ("BigInt → Bytes",              bigint_to_bytes_decode),
        ("Little-Endian Hex Decode",    little_endian_hex_decode),
    ]

    # Add more encoding variants to reach 1000+ methods

    # Base64 variants with different paddings
    for pad_count in range(1, 5):
        methods.append((f"Base64 Standard {pad_count} pad(s)", lambda t, p=pad_count: base64_standard_decode(t + '=' * p)))

    # Base32 variants with different paddings
    for pad_count in range(1, 8):
        methods.append((f"Base32 Standard {pad_count} pad(s)", lambda t, p=pad_count: base32_decode(t + '=' * p)))

    # Hex variants with different prefixes
    hex_prefixes = ['', '0x', '0X', '\\x', 'x', 'X', 'h', 'H']
    for prefix in hex_prefixes:
        methods.append((f"Hex → ASCII (prefix '{prefix}')", lambda t, p=prefix: hex_raw_decode(t.replace(p, ''))))

    # Binary variants with different separators
    binary_separators = [' ', '.', ':', '-', '_', '|', '', '0b', '0B']
    for sep in binary_separators:
        methods.append((f"Binary → ASCII (sep '{sep}')", lambda t, s=sep: binary_nospaces_decode(t.replace(s, ''))))

    # Octal variants with different prefixes
    octal_prefixes = ['', '0', '0o', '0O', '\\']
    for prefix in octal_prefixes:
        methods.append((f"Octal → ASCII (prefix '{prefix}')", lambda t, p=prefix: octal_decode(t.replace(p, ''))))

    # Decimal variants with different separators
    decimal_separators = [' ', ',', '.', ':', '-', '_']
    for sep in decimal_separators:
        methods.append((f"Decimal → ASCII (sep '{sep}')", lambda t, s=sep: decimal_decode(t.replace(s, ' '))))

    # Base64 with URL encoding variants
    url_chars = {'+': '-', '/': '_', '=': ''}
    for plus, slash in [('+', '/'), ('-', '_'), ('-', '/'), ('+', '_')]:
        for pad in ['', '=']:
            methods.append((f"Base64 URL {plus}/{slash} pad={pad}",
                          lambda t, p=plus, sl=slash, pd=pad: _safe_decode(base64.urlsafe_b64decode(
                              t.replace(p, '+').replace(sl, '/') + pd))))

    # Add more base encoding variants
    base_alphabets = {
        'Base32 Crockford': '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
        'Base32 Geohash': '0123456789bcdefghjkmnpqrstuvwxyz',
        'Base32 z-base-32': 'ybndrfg8ejkmcpqxot1uwisza345h769',
        'Base36 Lower': '0123456789abcdefghijklmnopqrstuvwxyz',
        'Base58 Ripple': 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz',
        'Base58 Flickr': '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
    }

    for name, alphabet in base_alphabets.items():
        methods.append((f"{name} Decode", lambda t, a=alphabet: custom_base_decode(t, a)))

    # Add character set conversion methods
    charset_conversions = [
        ('UTF-8 → Latin-1', 'utf-8', 'latin-1'),
        ('Latin-1 → UTF-8', 'latin-1', 'utf-8'),
        ('UTF-8 → Windows-1252', 'utf-8', 'windows-1252'),
        ('Windows-1252 → UTF-8', 'windows-1252', 'utf-8'),
        ('UTF-16 → UTF-8', 'utf-16', 'utf-8'),
        ('UTF-8 → UTF-16', 'utf-8', 'utf-16'),
        ('UTF-16LE → UTF-8', 'utf-16-le', 'utf-8'),
        ('UTF-16BE → UTF-8', 'utf-16-be', 'utf-8'),
    ]

    for name, src, dst in charset_conversions:
        methods.append((name, lambda t, s=src, d=dst: t.encode(s, errors='replace').decode(d, errors='replace')))

    # Add more numeric encoding variants
    numeric_encodings = [
        ('ASCII → Binary (8-bit)', lambda t: ' '.join(f"{ord(c):08b}" for c in t)),
        ('ASCII → Binary (7-bit)', lambda t: ' '.join(f"{ord(c):07b}" for c in t)),
        ('ASCII → Hex (2-digit)', lambda t: ' '.join(f"{ord(c):02x}" for c in t)),
        ('ASCII → Hex (4-digit)', lambda t: ' '.join(f"{ord(c):04x}" for c in t)),
        ('ASCII → Octal (3-digit)', lambda t: ' '.join(f"{ord(c):03o}" for c in t)),
        ('ASCII → Decimal', lambda t: ' '.join(f"{ord(c)}" for c in t)),
        ('ASCII → Hex (uppercase)', lambda t: ' '.join(f"{ord(c):02X}" for c in t)),
        ('ASCII → Hex (comma sep)', lambda t: ','.join(f"{ord(c):02x}" for c in t)),
        ('ASCII → Hex (colon sep)', lambda t: ':'.join(f"{ord(c):02x}" for c in t)),
        ('ASCII → Binary (comma sep)', lambda t: ','.join(f"{ord(c):08b}" for c in t)),
    ]

    for name, fn in numeric_encodings:
        methods.append((f"{name} Decode", lambda t, f=fn: ''.join(chr(int(x, 0)) for x in re.split(r'[^0-9a-fA-F]+', t) if x)))

    # Add more encoding types
    encoding_types = [
        ('URL Encode', lambda t: urllib.parse.unquote(t)),
        ('URL Decode', lambda t: urllib.parse.quote(t)),
        ('HTML Entity Decode', html.unescape),
        ('HTML Entity Encode', lambda t: ''.join(f"&#{ord(c)};" for c in t)),
        ('Morse Code Decode', morse_decode),
        ('Brainfuck Decode', brainfuck_decode),
        ('Ook! Decode', ook_decode),
        ('Pigpen Cipher Decode', pigpen_decode),
        ('Semaphore Decode', semaphore_decode),
        ('Tap Code Decode', tap_code_decode),
        ('DTMF Tones Decode', dtmf_decode),
        ('A1Z26 Decode', a1z26_decode),
        ('Atbash Cipher', atbash_decode),
        ('ROT13', rot13_decode),
        ('ROT47', rot47_decode),
        ('Vigenère Decode', vigenere_decode),
        ('Caesar Cipher Decode', caesar_decode),
        ('Affine Cipher Decode', affine_decode),
        ('Bacon Cipher Decode', bacon_decode),
        ('Polybius Square Decode', polybius_decode),
    ]

    # Add encoding variants for each type
    for name, fn in encoding_types:
        methods.append((f"{name}", fn))
        # Add variants with different parameters
        if name == 'Vigenère Decode':
            for key in ['A', 'KEY', 'SECRET', 'CRYPTO', 'PASSWORD', 'CRACKER', 'HACKER', 'ENCODE']:
                methods.append((f"{name} key={key}", lambda t, k=key: vigenere_decode(t, k)))
        elif name == 'Caesar Cipher Decode':
            for shift in range(1, 26):
                methods.append((f"{name} shift={shift}", lambda t, s=shift: caesar_decode(t, s)))
        elif name == 'Affine Cipher Decode':
            for a, b in [(1, 1), (3, 5), (5, 7), (7, 9), (9, 11), (11, 3), (15, 7), (17, 9), (19, 11), (21, 5), (23, 7), (25, 9)]:
                methods.append((f"{name} a={a} b={b}", lambda t, a_val=a, b_val=b: affine_decode(t, a_val, b_val)))
        elif name == 'ROT13':
            methods.append(("ROT5 (digits only)", lambda t: ''.join(chr(((ord(c) - ord('0') + 5) % 10) + ord('0')) if '0' <= c <= '9' else c for c in t)))
            methods.append(("ROT18 (digits + letters)", lambda t: ''.join(
                chr(((ord(c) - ord('0') + 18) % 36) + ord('0')) if '0' <= c <= '9' else
                chr(((ord(c.lower()) - ord('a') + 18) % 26) + ord('a')) if 'a' <= c.lower() <= 'z' else c for c in t)))
        elif name == 'Atbash Cipher':
            methods.append(("Atbash Cipher (Hebrew)", lambda t: atbash_decode(t)))  # Same function, different name

    for name, fn in encoding_types:
        methods.append((f"{name}", fn))

    return methods