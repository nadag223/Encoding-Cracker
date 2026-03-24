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
python cracker.py --list-methods              # print every supported method and exit
```

## Output

Every run saves a full log to `results_<timestamp>.txt`, sorted by confidence score from highest to lowest. The file includes every attempt that was made, even the low-scoring ones, so if the tool doesn't surface the answer automatically you can open the file in any editor and search manually.

The terminal prints a summary of the top 10 results while everything else runs in the background.

## Confidence Scoring

Each decoded result is scored from 0 to 100:

| Signal | Points |
|---|---|
| Output is mostly printable ASCII | +30 |
| Matches a CTF flag pattern like `flag{...}` or `CTF{...}` | +25 |
| Contains common English words | +20 |
| Output entropy is lower than input entropy | +15 |
| Output is non-empty and different from the input | +10 |

Results identical to the input are discarded automatically.

## Categories for --only

| Flag | What it covers |
|---|---|
| `base` | Base16 / 32 / 45 / 58 / 62 / 64 / 85 / 91 and variants |
| `rot` | ROT1-25, ROT47, ROT5 (digits only) |
| `classic` | Vigenere, Affine, Atbash, Beaufort, Playfair, Polybius, Bacon, Tap code |
| `transpos` | Rail Fence (2-5 rails), columnar transposition, string reversal variants |
| `xor` | Single-byte XOR 0x00-0xFF brute force, common key XOR |
| `text` | Morse, URL/HTML decode, T9, Dvorak/AZERTY remap, Braille, NATO phonetic |
| `compress` | Zlib, Gzip, Bzip2, Quoted-Printable, MIME header decode |
| `tricks` | First/last letter extraction, every-Nth char, zero-width removal, whitespace stego |
| `hash` | Hash type identification: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt |

## How it works

Before running anything, the tool checks the input for obvious signals: character set, length, entropy, known delimiters. Based on that it reorders the method queue so the most likely candidates run first, then works through everything else.

Each method either produces a decoded candidate or silently fails and moves on. Nothing crashes the run — every method is wrapped in a try/except block.

Once all methods have finished, results are written to the log file and the top 10 are printed to the terminal. If something looks close but not quite right, check the log for nearby entries with slightly different keys or variants.

## Tips

- If the input looks like random noise, start with `--only xor`. Single-byte XOR covers 256 variants in seconds.
- Vigenere is tried against a list of common CTF keys. If you have a hint about the key, add it to `wordlists/common_keys.txt`.
- Hash inputs (32, 40, 64, or 128 hex chars) are identified and labeled in the log but not cracked offline.
- The log is plain text. Open it and use Ctrl+F to search for a partial string you expect to see in the plaintext.
- Use `--only tricks` if the text might be hiding data in whitespace, zero-width characters, or letter position patterns.

## Project Structure

```
cracker.py              entry point, CLI, orchestration
methods/
  base_encodings.py     Base16 through Base91 and numeric variants
  rot_caesar.py         ROT1-25, ROT47, ROT5
  classic_ciphers.py    Vigenere, Affine, Atbash, Beaufort, Playfair
  transposition.py      Rail Fence, columnar, reversal
  xor_methods.py        XOR brute force, common keys
  text_symbols.py       Morse, URL, HTML, T9, keyboard remaps
  compression.py        Zlib, Gzip, Bzip2, MIME
  string_tricks.py      Letter extraction, Nth-char, whitespace stego
  hash_detect.py        Hash type identification
utils/
  scorer.py             confidence scoring
  detector.py           pre-run encoding hints
  reporter.py           TXT log writer and terminal output
wordlists/
  common_keys.txt       keys tried for Vigenere and keyword ciphers
```