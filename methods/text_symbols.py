"""Text & symbol encodings: Morse, URL, HTML, Unicode, T9, NATO, Braille, keyboard maps."""
import re
from urllib.parse import unquote, unquote_plus
from html import unescape
import unicodedata

# ── Morse code ────────────────────────────────────────────────────────────────

MORSE_TO_CHAR = {
    '.-':'A','-.':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
    '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
    '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
    '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
    '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
    '---..':'8','----.':'9'
}
CHAR_TO_MORSE = {v:k for k,v in MORSE_TO_CHAR.items()}

def morse_decode(text: str):
    try:
        words = text.strip().split('   ')
        result = []
        for word in words:
            letters = word.strip().split(' ')
            result.append(''.join(MORSE_TO_CHAR.get(l,'?') for l in letters if l))
        return ' '.join(result)
    except Exception:
        return None

def morse_decode_slash(text: str):
    # Variant: '/' separates words, ' ' separates letters
    try:
        text2 = text.replace('/', '   ')
        return morse_decode(text2)
    except Exception:
        return None

# ── NATO phonetic alphabet ────────────────────────────────────────────────────

NATO = {
    'ALPHA':'A','BRAVO':'B','CHARLIE':'C','DELTA':'D','ECHO':'E',
    'FOXTROT':'F','GOLF':'G','HOTEL':'H','INDIA':'I','JULIET':'J',
    'KILO':'K','LIMA':'L','MIKE':'M','NOVEMBER':'N','OSCAR':'O',
    'PAPA':'P','QUEBEC':'Q','ROMEO':'R','SIERRA':'S','TANGO':'T',
    'UNIFORM':'U','VICTOR':'V','WHISKEY':'W','XRAY':'X','YANKEE':'Y','ZULU':'Z'
}

def nato_decode(text: str):
    try:
        return ''.join(NATO.get(w.upper(),'?') for w in text.strip().split() if w)
    except Exception:
        return None

# ── T9 / multi-tap ────────────────────────────────────────────────────────────

T9_MAP = {
    '2':'ABC','3':'DEF','4':'GHI','5':'JKL',
    '6':'MNO','7':'PQRS','8':'TUV','9':'WXYZ'
}

def t9_decode(text: str):
    # Each group of repeated digits → letter (count selects letter in group)
    try:
        result = []
        for group in re.findall(r'(\d)\1*', text):
            digit = group[0]; count = len(group)
            letters = T9_MAP.get(digit, '')
            if letters:
                result.append(letters[(count-1) % len(letters)])
        return ''.join(result) or None
    except Exception:
        return None

# ── URL / HTML / Unicode ──────────────────────────────────────────────────────

def url_decode(text: str):
    try:
        return unquote(text)
    except Exception:
        return None

def double_url_decode(text: str):
    try:
        return unquote(unquote(text))
    except Exception:
        return None

def html_decode(text: str):
    try:
        return unescape(text)
    except Exception:
        return None

def unicode_escape_decode(text: str):
    try:
        return text.encode('utf-8').decode('unicode_escape')
    except Exception:
        return None

def punycode_decode(text: str):
    try:
        return text.encode('ascii').decode('idna')
    except Exception:
        return None

# ── Braille ───────────────────────────────────────────────────────────────────

BRAILLE = {
    '⠁':'A','⠃':'B','⠉':'C','⠙':'D','⠑':'E','⠋':'F','⠛':'G','⠓':'H',
    '⠊':'I','⠚':'J','⠅':'K','⠇':'L','⠍':'M','⠝':'N','⠕':'O','⠏':'P',
    '⠟':'Q','⠗':'R','⠎':'S','⠞':'T','⠥':'U','⠧':'V','⠺':'W','⠭':'X',
    '⠽':'Y','⠵':'Z'
}

def braille_decode(text: str):
    try:
        return ''.join(BRAILLE.get(c, c) for c in text)
    except Exception:
        return None

# ── Keyboard layout maps ──────────────────────────────────────────────────────

DVORAK_TO_QWERTY = str.maketrans(
    "'-,.pyfgcrl/=aoeuidhtns;qjkxbmwvz",
    "qwertyuiop[]asdfghjkl;'zxcvbnm,./"
)

AZERTY_TO_QWERTY = str.maketrans(
    'azertyuiopqsdfghjklmwxcvbn',
    'qwzertyuiopasdfghjklmxcvbn'
)

def dvorak_to_qwerty(text: str):
    try:
        return text.translate(DVORAK_TO_QWERTY)
    except Exception:
        return None

def azerty_to_qwerty(text: str):
    try:
        return text.translate(AZERTY_TO_QWERTY)
    except Exception:
        return None

# ── Method registry ───────────────────────────────────────────────────────────

def get_methods():
    return [
        ("URL Decode",                  url_decode),
        ("Double URL Decode",           double_url_decode),
        ("HTML Entity Decode",          html_decode),
        ("Unicode Escape Decode",       unicode_escape_decode),
        ("Punycode Decode",             punycode_decode),
        ("Morse Code Decode (spaces)",  morse_decode),
        ("Morse Code Decode (slash/)",  morse_decode_slash),
        ("NATO Phonetic → Letters",     nato_decode),
        ("T9 Multi-tap Decode",         t9_decode),
        ("Braille Unicode → Text",      braille_decode),
        ("Dvorak → QWERTY",             dvorak_to_qwerty),
        ("AZERTY → QWERTY",             azerty_to_qwerty),
    ]
