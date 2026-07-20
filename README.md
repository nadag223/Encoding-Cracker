# CTF Encoding Cracker

Tries every known encoding and cipher on your input. Ranks results by confidence score and saves a full log so you can scan through it manually if nothing obvious comes up automatically.

## Install

```
pip install -r requirements.txt
```

Python 3.8 or newer is required.

## Usage

```
python cracker.py "SGVsbG8gV29ybGQ="          # basic
python cracker.py "TEXT" --show-all           # show all results in terminal, not just top 10
python cracker.py "TEXT" --output out.txt     # custom output filename
python cracker.py "TEXT" --only base,rot,xor  # run specific categories only
python cracker.py "TEXT" --max-depth 3        # enable multi-layer pipeline (default: 3)
python cracker.py "TEXT" --no-parallel       # disable parallel processing
python cracker.py --list-methods              # print every supported method and exit
```

## Build System

The project now includes build scripts for easy setup and maintenance:

```
# Setup and test the environment
python build.py setup    # Install dependencies
python build.py test     # Run basic tests
python build.py clean    # Clean build artifacts
python build.py          # Run all (setup + test)

# Clean specific items
python clean.py pycache  # Clean only __pycache__ directories
python clean.py results  # Clean only results directory
```

## New Features

### Multi-layer Decoding Pipeline
The tool now supports recursive decoding of results that score above a threshold (default: 50/100). This handles common CTF patterns like `base64(rot13(hex(...)))` automatically.

### Parallel Processing
Expensive methods (XOR brute force, Vigenere, substitution solvers) now run in parallel across multiple CPU cores by default. Use `--no-parallel` to disable.

### Enhanced Detection
Structural fingerprinting detects JWT, PEM, compressed data, and file formats before brute-forcing, prioritizing the most likely methods.

### Multi-language Support
Scoring now works with English, Spanish, and Hebrew text, with n-gram frequency tables for each language.

## Confidence Scoring

Each decoded result is scored from 0 to 100:

| Signal | Points |
|---|---|
| Output is mostly printable ASCII | +30 |
| Matches a CTF flag pattern like `flag{...}` or `CTF{...}` | +25 |
| Contains common words (English/Spanish/Hebrew) | +20 |
| Output entropy is lower than input entropy | +15 |
| Output is non-empty and different from the input | +10 |
| Good n-gram frequency score | +10 |
| Possible substitution cipher pattern | +10 |

Results identical to the input are discarded automatically.

## Categories for --only

| Flag | What it covers |
|---|---|
| `base` | Base16, Base32, Base36, Base45, Base58, Base62, Base64, Base85 (RFC1924/Ascii85/Z85), Base91, Base92, Base122, UUEncode, yEnc, Punycode, UTF-7, binary/hex/octal (BE/LE), nibble swap |
| `rot` | ROT1-25, ROT47, ROT5 (digits only) |
| `classic` | Vigenere, Affine, Atbash, Beaufort, Playfair, Polybius, Bacon, Tap code, Hill Cipher, Autokey, Bifid, Trifid, Four-Square, Two-Square, ADFGVX, ADFGX, Running Key, Enigma simulator |
| `transpos` | Rail Fence (2-5 rails), columnar transposition, string reversal variants |
| `xor` | Single-byte XOR 0x00-0xFF brute force, common key XOR, multi-byte XOR with Kasiski/frequency analysis, known-plaintext XOR (magic bytes), bit rotation (ROL/ROR 1-7) |
| `text` | Morse, URL/HTML decode, T9, Dvorak/AZERTY remap, Braille, NATO phonetic, Baudot, Excess-3, Gray code |
| `compress` | Zlib, Gzip, Bzip2, Quoted-Printable, MIME header decode, LZW |
| `tricks` | First/last letter extraction, every-Nth char, zero-width removal, whitespace stego, homoglyph normalization, ADD/SUB/Multiplicative ciphers |
| `hash` | Hash type identification: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt |
| `subst` | Simple substitution solver (hill-climbing/genetic), Caesar brute force |

## How it works

1. **Structural Detection**: The tool first checks for obvious signals like JWT structure, PEM headers, compression magic bytes, and file formats.
2. **Method Queue**: Based on detection results, the most likely methods are prioritized.
3. **Parallel Execution**: Expensive methods run in parallel across CPU cores.
4. **Multi-layer Pipeline**: Results scoring above 50/100 are recursively decoded up to the specified depth (default: 3).
5. **Deduplication**: Identical intermediate results are skipped to prevent exponential blowup.
6. **Scoring**: Each result is scored based on multiple language models and structural patterns.
7. **Output**: Results are saved to a log file and the top 10 are displayed in the terminal.

## Multi-layer Pipeline

When a result scores above the threshold (50/100), the tool automatically runs the full method queue on that result, creating a chain like:

```
hex → rot13 → base64 → flag{...}
```

The log file shows the full method chain for each result. The `--max-depth` flag controls how many layers deep the pipeline goes (default: 3).

## Tips

- If the input looks like random noise, start with `--only xor`. Single-byte XOR covers 256 variants in seconds.
- For multi-layer challenges, increase `--max-depth` (up to 5).
- Vigenere is tried against common CTF keys. Add custom keys to `wordlists/running_key_sources.txt`.
- Hash inputs (32, 40, 64, or 128 hex chars) are identified but not cracked offline.
- The log is plain text. Use Ctrl+F to search for expected plaintext patterns.
- Use `--only tricks` for steganography (whitespace, zero-width, letter positions).
- For ADFGVX/ADFGX: look for strings containing only A,D,F,G,V,X letters.
- Hill Cipher: try common 2x2 matrices with determinant coprime to 26.
- Enigma: the tool tries common historical configurations (Wehrmacht M3).
- Running Key: uses text from `wordlists/running_key_sources.txt`.
- Simple substitution: the solver works without a wordlist using n-gram statistics.
- Multi-byte XOR: uses Kasiski examination and frequency analysis to find key length.
- Known-plaintext XOR: detects file magic bytes (PNG, ZIP, PDF, etc.) and derives keys.

## Project Structure

```
cracker.py                  entry point, CLI, orchestration
methods/
  base_encodings.py         Base16 through Base122, UUEncode, yEnc, Punycode, UTF-7
  rot_caesar.py             ROT1-25, ROT47, ROT5
  classic_ciphers.py        Vigenere, Affine, Atbash, Beaufort, Playfair, Polybius,
                            Bacon, Tap, Hill, Autokey, Bifid, Trifid, Four-Square,
                            Two-Square, ADFGVX, ADFGX, Running Key, Enigma
  transposition.py          Rail Fence, columnar, reversal
  xor_methods.py            XOR brute force, multi-byte XOR, known-plaintext, bit rotation
  text_symbols.py           Morse, URL/HTML, T9, keyboard remaps, Baudot, Excess-3, Gray code
  compression.py            Zlib, Gzip, Bzip2, Quoted-Printable, MIME, LZW
  string_tricks.py          Letter extraction, Nth-char, whitespace stego, homoglyphs
  hash_detect.py            Hash type identification
  substitution_ciphers.py   Simple substitution solver, Caesar brute force
utils/
  scorer.py                 confidence scoring with multi-language support
  detector.py               structural fingerprinting and encoding detection
  reporter.py               TXT log writer and terminal output
wordlists/
  running_key_sources.txt   texts used for Running Key cipher
```