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
Scoring uses offline frequency data for many languages. Real-word frequency is
looked up with the [`wordfreq`](https://github.com/rspeer/wordfreq) library
(bundled frequency tables — no network calls), tried across a curated set of
languages (English, Spanish, Hebrew, German, French, and more). For a general
"does this look like structured human text vs. random noise" signal, a
self-trained, offline 2-character **Markov naturalness model** is used — built
once from `wordlists/corpus_en.txt` and persisted to
`wordlists/markov_model.json`, so it is never retrained at runtime. See
*Confidence Scoring* below for how these combine.

## Confidence Scoring

Each decoded result is scored from 0 to 100 using a **normalized weighted
model**. This replaced an earlier additive point table that *saturated at 100*
on weak multi-signal matches — letting multi-layer gibberish chains tie and
outrank clean single-layer decodes (see the regression test in
`tests/test_scoring.py`). Every signal is a normalized value in `[0.0, 1.0]`
and they are combined by a fixed weighted formula, so weak signals can no
longer stack to the cap.

### The formula

```
if strong_structural_match:                 # dominant signal, short-circuits
    base = 0.90 + 0.10 * ascii_ratio
else:
    base = 0.30 * ascii_ratio
         + 0.25 * language_score
         + 0.20 * entropy_drop
         + 0.15 * diff_from_input
         + 0.10 * weak_pattern_bonus

decay = 0.85 ** max(0, pipeline_depth - 1)  # no penalty at depth 1
score = round(base * decay * 100, 1)
```

### Signals (all normalized 0.0–1.0)

| Signal | What it measures | Weight |
|---|---|---|
| `strong_structural_match` | A *genuinely valid* domain (labels + known TLD), JWT, PEM block, or recognized file magic bytes. Set only by precise structural detectors — never loose substring heuristics. | dominant (short-circuits to ~0.90–1.00 base) |
| `ascii_ratio` | Fraction of printable ASCII characters | 0.30 |
| `language_score` | `max(wordfreq lexical score, Markov naturalness)` — real-word frequency across languages, or natural-character-transition statistics | 0.25 |
| `entropy_drop` | How much Shannon entropy dropped vs. the input | 0.20 |
| `diff_from_input` | How unlike the input the decoded result is | 0.15 |
| `weak_pattern_bonus` | Capped bonus from lightweight patterns: CTF flag template, JSON/HTML shape | 0.10 |

### Pipeline-depth decay

A single-layer decode (depth 1) gets **no penalty**. Each additional decode
layer multiplies the score by **0.85**, so a clean one-layer valid-domain
result scores 100 while the same shape produced by a 2-layer chain scores 85, a
3-layer chain 72.25, and so on. This makes deep chains increasingly skeptical
rather than giving them a free pass — the fix that stops
`dvorak → qwerty → caesar` gibberish from tying a real decode.

### Language signal details

* **wordfreq** — fraction of alphabetic tokens (length ≥ 3) that are frequent
  words in *some* supported language; tokens of length 2 are excluded because
  almost every 2-letter string is a real word *somewhere* across wordfreq's ~40
  languages, which made short gibberish look plausible. Per-token lookups are
  memoized and English (and a few primary languages) are tried first; the full
  language sweep only runs when no primary language already explains the
  tokens. This keeps a full run fast.
* **Markov naturalness** — a 2-character transition model trained once from
  `wordlists/corpus_en.txt` and stored at `wordlists/markov_model.json`. The
  scorer computes an average per-character log-probability and squashes it
  through a logistic curve into 0–1, so real English prose lands ~0.4–0.6 and
  random symbols/letters collapse toward 0.
* The two combine via **max**: a candidate that is plausibly human text in
  *either* sense (real words or natural bigram statistics) scores well; a domain
  like `goramli.bsmch.idf.il` (valid but not dictionary words) is correctly low
  on this signal and relies on the structural detector instead.

Both signals run fully offline — `wordfreq` ships its data bundled and the
Markov model is trained locally. No code path in the scorer or detector makes a
network request.

Results identical to the input are discarded automatically.

### Reproducing / regressing the scoring model

`tests/test_scoring.py` pins the bug report this overhaul fixed: the clean
single-layer domain decode `goramli.bsmch.idf.il` must outrank (and by a wide
margin) the multi-layer Dvorak→QWERTY→Caesar gibberish that previously tied it
at 100/100. It also asserts the domain regex rejects punctuation-heavy
gibberish and accepts fully valid multi-label domains. Run with
`py tests/test_scoring.py` (no pytest required) or `pytest`.

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
- Simple substitution: the solver works without a wordlist using the offline Markov naturalness model as its fitness function (hill-climbing + genetic algorithm).
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
  scorer.py                 normalized weighted confidence scoring (wordfreq + Markov)
  detector.py               structural fingerprinting + valid domain/JWT/PEM/magic detection
  markov_language.py        offline 2-char Markov naturalness model (trained + persisted)
  reporter.py               TXT log writer and terminal output
wordlists/
  running_key_sources.txt   texts used for Running Key cipher
  corpus_en.txt             English corpus the Markov model is trained from
  markov_model.json         persisted trained Markov model (built on first use)
tests/
  test_scoring.py           regression tests for the scoring + structural detection
```