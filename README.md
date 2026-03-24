# CTF Encoding Cracker

Tries every known encoding/cipher on your input and ranks results by confidence.

## Install
```
pip install -r requirements.txt
```

## Usage
```
python cracker.py "SGVsbG8gV29ybGQ="          # basic
python cracker.py "TEXT" --show-all           # show all results
python cracker.py "TEXT" --output out.txt     # custom output file
python cracker.py "TEXT" --only base,rot,xor  # specific categories
python cracker.py --list-methods              # list everything
```

## Categories for --only
`base` `rot` `classic` `transpos` `xor` `text` `compress` `tricks` `hash`

## Output
Results saved to `results_<timestamp>.txt`, sorted by confidence score (0–100).
