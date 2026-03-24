"""
CTF Encoding Cracker — main entry point.
Usage:
  python cracker.py "TEXT"
  python cracker.py "TEXT" --show-all
  python cracker.py "TEXT" --output myfile.txt
  python cracker.py "TEXT" --only base,rot,xor
  python cracker.py --list-methods
"""
import sys
import os
import argparse
from datetime import datetime

# ── optional deps ─────────────────────────────────────────────────────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

def _c(code, text):
    return (code + text + Style.RESET_ALL) if HAS_COLOR else text

# ── internal imports ──────────────────────────────────────────────────────────
from methods import base_encodings, rot_caesar, classic_ciphers, transposition
from methods import xor_methods, text_symbols, compression, string_tricks, hash_detect
from utils import scorer, detector, reporter

# ── method categories ─────────────────────────────────────────────────────────
CATEGORY_MAP = {
    'base':        base_encodings.get_methods,
    'rot':         rot_caesar.get_methods,
    'classic':     classic_ciphers.get_methods,
    'transpos':    transposition.get_methods,
    'xor':         xor_methods.get_methods,
    'text':        text_symbols.get_methods,
    'compress':    compression.get_methods,
    'tricks':      string_tricks.get_methods,
    'hash':        hash_detect.get_methods,
}

def load_methods(only: list | None = None) -> list:
    """Load all (name, fn) pairs, optionally filtered by category."""
    all_methods = []
    for key, loader in CATEGORY_MAP.items():
        if only and key not in only:
            continue
        try:
            all_methods.extend(loader())
        except Exception as e:
            print(f"[!] Failed loading category '{key}': {e}")
    return all_methods

def run_method(name: str, fn, text: str) -> dict | None:
    """Execute one method; return result dict or None."""
    try:
        result = fn(text)
        if result is None:
            return None
        s, notes = scorer.score(text, str(result))
        if s == -99:
            return None
        return {'method': name, 'result': result, 'score': s, 'notes': notes}
    except Exception:
        return None

def list_methods():
    """Print all supported methods and exit."""
    methods = load_methods()
    print(f"\n{'=' * 50}")
    print(f"CTF Cracker — {len(methods)} supported methods")
    print(f"{'=' * 50}")
    for i, (name, _) in enumerate(methods, 1):
        print(f"  {i:4d}. {name}")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='CTF Encoding Cracker')
    parser.add_argument('text', nargs='?', help='Input string to crack')
    parser.add_argument('--show-all', action='store_true', help='Show all results in terminal')
    parser.add_argument('--output', default=None, help='Output filename')
    parser.add_argument('--list-methods', action='store_true', help='List all methods and exit')
    parser.add_argument('--only', default=None,
                        help='Comma-separated categories: base,rot,xor,classic,transpos,text,compress,tricks,hash')
    args = parser.parse_args()

    if args.list_methods:
        list_methods()

    if not args.text:
        text = input("Enter encoded text: ").strip()
        if not text:
            print("No input provided.")
            sys.exit(1)
    else:
        text = args.text
    only = [x.strip() for x in args.only.split(',')] if args.only else None
    methods = load_methods(only)

    # Auto-detect hints
    hints = detector.detect(text)
    for h in hints:
        print(_c(Fore.CYAN if HAS_COLOR else '', f"[*] Auto-detected: {h}"))

    print(_c(Fore.YELLOW if HAS_COLOR else '', f"[*] Running {len(methods)} methods..."))

    # Run all methods with progress bar
    results = []
    if HAS_TQDM:
        it = tqdm(methods, ncols=70, unit='method')
    else:
        it = methods

    for name, fn in it:
        r = run_method(name, fn, text)
        if r:
            results.append(r)

    # Save to file
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs("results", exist_ok=True)
    output_path = args.output or os.path.join("results", f"results_{ts}.txt")
    reporter.save_results(results, text, output_path)

    # Print terminal summary
    reporter.print_summary(results, output_path, show_all=args.show_all)

if __name__ == '__main__':
    main()