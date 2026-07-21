"""
CTF Encoding Cracker — main entry point.
Usage:
  python cracker.py "TEXT"
  python cracker.py "TEXT" --show-all
  python cracker.py "TEXT" --output myfile.txt
  python cracker.py "TEXT" --only base,rot,xor
  python cracker.py "TEXT" --max-depth 3
  python cracker.py "TEXT" --no-parallel
  python cracker.py --list-methods
"""
import sys
import os
import argparse
from datetime import datetime
import multiprocessing
from functools import partial

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


class _Spinner:
    """Simple spinner for when tqdm is not available."""
    def __init__(self, desc="", total=100):
        self.desc = desc
        self.total = total
        self.spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.idx = 0
        self.count = 0
        self.last_update = 0

    def update(self, n=1):
        self.count += n
        self.idx = (self.idx + 1) % len(self.spinner)
        # Only update every 100ms to avoid flooding the terminal
        import time
        now = time.time()
        if now - self.last_update > 0.1:
            self.last_update = now
            percent = (self.count / self.total) * 100 if self.total > 0 else 0
            print(f"\r{_c(Fore.CYAN, self.desc)} {_c(Fore.YELLOW, self.spinner[self.idx])} {_c(Fore.GREEN, f'{self.count}/{self.total}')} ({percent:.1f}%) methods", end="", flush=True)

    def set_description(self, desc):
        self.desc = desc
        self.last_update = 0  # force update

    def close(self):
        print("\r" + " " * 80 + "\r", end="", flush=True)

def _c(code, text):
    return (code + text + Style.RESET_ALL) if HAS_COLOR else text

# ── internal imports ──────────────────────────────────────────────────────────
from methods import base_encodings, rot_caesar, classic_ciphers, transposition
from methods import xor_methods, text_symbols, compression, string_tricks, hash_detect
from methods import substitution_ciphers
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
    'subst':       substitution_ciphers.get_methods,
}

# ── Multi-layer pipeline constants ───────────────────────────────────────────
PIPELINE_THRESHOLD = 50  # Score threshold to trigger pipeline
MAX_PIPELINE_DEPTH = 3   # Max recursion depth
MAX_TOTAL_ATTEMPTS = 1000  # Global budget to prevent explosion

# ── Method registry ───────────────────────────────────────────────────────────

def load_methods(only: list | None = None) -> list:
    """Load all method definitions, optionally filtered by category.

    Returns list of method tuples where each tuple is either:
    - (name, function) for simple methods
    - (name, method_type, method_params) for complex methods
    """
    all_methods = []
    for key, loader in CATEGORY_MAP.items():
        if only and key not in only:
            continue
        try:
            methods = loader()
            all_methods.extend(methods)
        except Exception as e:
            print(f"[!] Failed loading category '{key}': {e}")
    return all_methods

def run_method(name: str, fn, text: str, pipeline_depth: int = 1) -> dict | None:
    """Execute one method; return result dict or None.

    ``pipeline_depth`` (1 = single layer) is forwarded to the scorer so deeper
    decode chains get the depth-decay penalty. The scorer uses a normalized
    weighted model; see ``utils/scorer.py``.
    """
    try:
        result = fn(text)
        if result is None:
            return None
        s, notes = scorer.score(text, str(result), pipeline_depth)
        if s == -99:
            return None
        return {'method': name, 'result': result, 'score': s, 'notes': notes}
    except Exception as e:
        return {
            'method': name,
            'result': f"[!] {name} failed: {str(e)}",
            'score': 0,
            'notes': [f"Error: {str(e)}"]
        }

def run_method_parallel(args: tuple) -> dict | None:
    """Worker for parallel execution; avoids pickling by using method
    names/parameters instead of bound functions.

    ``args`` is ``(name, method_type, method_params, text)`` or, with depth
    threading, ``(name, method_type, method_params, text, pipeline_depth)``.
    All methods are routed through ``scorer.score`` with the correct pipeline
    depth so the scoring model applies uniformly in parallel and sequential
    paths. (Previously this branch called undefined ``score_result`` /
    ``generate_notes`` helpers, which silently zeroed every parallel classic-
    cipher result.)
    """
    if len(args) == 5:
        name, method_type, method_params, text, pipeline_depth = args
    else:
        name, method_type, method_params, text = args
        pipeline_depth = 1

    try:
        if method_type == "simple":
            # Simple (name, fn) method dispatched in the parallel pool.
            fn = method_params
            result = fn(text)
        elif method_type == "vigenere":
            from methods.classic_ciphers import _vigenere
            result = _vigenere(text, method_params, decrypt=True)
        elif method_type == "beaufort":
            from methods.classic_ciphers import _beaufort
            result = _beaufort(text, method_params)
        elif method_type == "affine":
            from methods.classic_ciphers import _affine_decrypt
            a, b = method_params
            result = _affine_decrypt(text, a, b)
        elif method_type == "playfair":
            from methods.classic_ciphers import _playfair_decrypt
            result = _playfair_decrypt(text, method_params)
        elif method_type == "hill":
            from methods.classic_ciphers import hill_decrypt_2x2
            result = hill_decrypt_2x2(text, method_params)
        elif method_type == "autokey":
            from methods.classic_ciphers import autokey_decrypt
            result = autokey_decrypt(text, method_params)
        elif method_type == "bifid":
            from methods.classic_ciphers import bifid_decrypt
            key, period = method_params
            result = bifid_decrypt(text, key, period)
        elif method_type == "trifid":
            from methods.classic_ciphers import trifid_decrypt
            key, period = method_params
            result = trifid_decrypt(text, key, period)
        elif method_type == "foursquare":
            from methods.classic_ciphers import foursquare_decrypt
            key1, key2 = method_params
            result = foursquare_decrypt(text, key1, key2)
        elif method_type == "twosquare":
            from methods.classic_ciphers import twosquare_decrypt
            key1, key2, vertical = method_params
            result = twosquare_decrypt(text, key1, key2, vertical)
        elif method_type == "adfgvx":
            from methods.classic_ciphers import adfgvx_decrypt
            key, polybius_key = method_params
            result = adfgvx_decrypt(text, key, polybius_key)
        elif method_type == "adfgx":
            from methods.classic_ciphers import adfgx_decrypt
            key, polybius_key = method_params
            result = adfgx_decrypt(text, key, polybius_key)
        elif method_type == "running_key":
            from methods.classic_ciphers import running_key_decrypt
            result = running_key_decrypt(text, method_params)
        elif method_type == "enigma":
            from methods.classic_ciphers import _enigma_process
            rotors, reflector, rings, positions, plugboard = method_params
            result = _enigma_process(text, rotors, reflector, rings, positions, plugboard)
        elif method_type == "xor_single":
            from methods.xor_methods import xor_single_byte
            result = xor_single_byte(text, method_params)
        elif method_type == "xor_keyword":
            from methods.xor_methods import xor_key_keyword
            result = xor_key_keyword(text, method_params)
        elif method_type == "xor_multi":
            from methods.xor_methods import xor_multi_byte_kasiski
            result = xor_multi_byte_kasiski(text)
        elif method_type == "xor_known":
            from methods.xor_methods import xor_known_plaintext
            result = xor_known_plaintext(text)
        elif method_type == "rol":
            from methods.xor_methods import rol_bits
            result = rol_bits(text, method_params)
        elif method_type == "ror":
            from methods.xor_methods import ror_bits
            result = ror_bits(text, method_params)
        else:
            return run_method(name, method_params, text, pipeline_depth)

        if result is None:
            return None
        s, notes = scorer.score(text, str(result), pipeline_depth)
        if s == -99:
            return None
        return {'method': name, 'result': result, 'score': s, 'notes': notes}
    except Exception as e:
        return {
            'method': name,
            'result': f"[!] {name} failed: {str(e)}",
            'score': 0,
            'notes': [f"Error: {str(e)}"]
        }

# Helper functions for method definitions - these now return tuples with method info instead of functions

# Helper functions for method definitions - these return tuples with method info instead of functions
# Format: (method_name, method_type, method_params)

def _make_vigenere_fn(key: str):
    return (f"Vigenere key={key}", "vigenere", key)

def _make_beaufort_fn(key: str):
    return (f"Beaufort key={key}", "beaufort", key)

def _make_affine_fn(a: int, b: int):
    return (f"Affine a={a} b={b}", "affine", (a, b))

def _make_playfair_fn(key: str):
    return (f"Playfair key={key}", "playfair", key)

def _make_hill_fn(key_matrix: list):
    return (f"Hill 2x2 key={key_matrix}", "hill", key_matrix)

def _make_autokey_fn(key: str):
    return (f"Autokey key={key}", "autokey", key)

def _make_bifid_fn(key: str, period: int):
    return (f"Bifid key={key} period={period}", "bifid", (key, period))

def _make_trifid_fn(key: str, period: int):
    return (f"Trifid key={key} period={period}", "trifid", (key, period))

def _make_foursquare_fn(key1: str, key2: str):
    return (f"Four-Square key1={key1} key2={key2}", "foursquare", (key1, key2))

def _make_twosquare_fn(key1: str, key2: str, vertical: bool):
    mode_str = "vertical" if vertical else "horizontal"
    return (f"Two-Square {mode_str} key1={key1} key2={key2}", "twosquare", (key1, key2, vertical))

def _make_adfgvx_fn(key: str, polybius_key: str):
    return (f"ADFGVX key={key} polybius={polybius_key}", "adfgvx", (key, polybius_key))

def _make_adfgx_fn(key: str, polybius_key: str):
    return (f"ADFGX key={key} polybius={polybius_key}", "adfgx", (key, polybius_key))

def _make_running_key_fn(running_key: str):
    return (f"Running Key source={running_key[:10]}...", "running_key", running_key)

def _make_enigma_fn(config: dict):
    return (f"Enigma config rotors={config['rotors']} refl={config['reflector']}", "enigma", (config['rotors'], config['reflector'], config['rings'], config['positions'], config['plugboard']))

def list_methods():
    """Print all supported methods and exit."""
    methods = load_methods()
    print(f"\n{'=' * 50}")
    print(f"CTF Cracker - {len(methods)} supported methods")
    print(f"{'=' * 50}")
    for i, method_info in enumerate(methods, 1):
        # Extract name from method info (could be (name, fn) or (name, type, params))
        name = method_info[0]
        # Replace any Unicode characters that might cause encoding issues
        safe_name = name.encode('ascii', 'replace').decode('ascii')
        print(f"  {i:4d}. {safe_name}")
    print(f"\nCategories: {', '.join(CATEGORY_MAP.keys())}")
    sys.exit(0)

# ── Multi-layer decoding pipeline ────────────────────────────────────────────

def run_pipeline(text: str, methods: list, max_depth: int = MAX_PIPELINE_DEPTH,
                  seen: set = None, attempt_count: int = 0, parallel: bool = True,
                  depth: int = 1, progress_bar=None) -> list[dict]:
    """Run the multi-layer decoding pipeline with deduplication and budget control.

    ``depth`` is the 1-based count of decode layers applied so far to reach the
    current ``text`` (1 = the first layer on the raw input). It is forwarded to
    the scorer so each result knows its own pipeline depth for the depth-decay
    penalty: depth 1 incurs no penalty, each additional layer multiplies by 0.85.

    ``progress_bar``: if provided, a tqdm progress bar that will be updated with
    the current method count and layer depth.
    """
    if seen is None:
        seen = set()
    if attempt_count >= MAX_TOTAL_ATTEMPTS:
        return []

    # Run all methods on current text
    results = []

    # Separate expensive methods from regular ones
    expensive_methods = []
    regular_methods = []

    for method_info in methods:
        if len(method_info) == 2:
            # Simple method: (name, function)
            name, fn = method_info
            if any(x in name.lower() for x in ['xor', 'vigenere', 'substitution', 'hill', 'autokey']):
                expensive_methods.append((name, "simple", fn))
            else:
                regular_methods.append((name, "simple", fn))
        else:
            # Classic cipher method: (name, method_type, method_params)
            name, method_type, method_params = method_info
            expensive_methods.append((name, method_type, method_params))

    # Process regular methods (thread depth into the scorer)
    for name, method_type, method_info in regular_methods:
        if progress_bar:
            progress_bar.set_description(_c(Fore.CYAN, f"Layer {depth} | Running Methods"))
            progress_bar.update(1)

        if method_type == "simple":
            r = run_method(name, method_info, text, depth)
        else:
            r = run_method_parallel((name, method_type, method_info, text, depth))

        if r:
            results.append(r)
            attempt_count += 1
            if attempt_count >= MAX_TOTAL_ATTEMPTS:
                break

    # Process expensive methods in parallel if enabled
    if expensive_methods and attempt_count < MAX_TOTAL_ATTEMPTS and parallel:
        with multiprocessing.Pool(min(multiprocessing.cpu_count(), len(expensive_methods))) as pool:
            args_list = [
                (name, method_type, method_params, text, depth)
                for name, method_type, method_params in expensive_methods
            ]
            parallel_results = pool.map(run_method_parallel, args_list)
            for r in parallel_results:
                if progress_bar:
                    progress_bar.update(1)
                if r:
                    results.append(r)
                    attempt_count += 1
                    if attempt_count >= MAX_TOTAL_ATTEMPTS:
                        break
    elif expensive_methods and attempt_count < MAX_TOTAL_ATTEMPTS:
        # Sequential fallback if parallel disabled
        for name, method_type, method_params in expensive_methods:
            if progress_bar:
                progress_bar.update(1)
            r = run_method_parallel((name, method_type, method_params, text, depth))
            if r:
                results.append(r)
                attempt_count += 1
                if attempt_count >= MAX_TOTAL_ATTEMPTS:
                    break

    # Deduplicate results
    unique_results = []
    seen_results = set()
    for r in results:
        result_str = str(r['result'])
        if result_str not in seen_results:
            seen_results.add(result_str)
            unique_results.append(r)

    # Check for pipeline candidates
    pipeline_results = []
    for r in unique_results:
        if r['score'] >= PIPELINE_THRESHOLD and max_depth > 0:
            # Check if we've seen this result before
            result_str = str(r['result'])
            if result_str not in seen:
                seen.add(result_str)
                # Recursively run pipeline on this intermediate result. The
                # nested layer is one deeper, so it scores with depth + 1.
                nested_results = run_pipeline(
                    result_str, methods, max_depth - 1, seen, attempt_count,
                    parallel, depth=depth + 1, progress_bar=progress_bar,
                )
                # Add method chain to nested results
                for nr in nested_results:
                    nr['method'] = f"{r['method']} -> {nr['method']}"
                    nr['notes'].append(f"Pipeline: {r['method']} produced intermediate result")
                pipeline_results.extend(nested_results)

    return unique_results + pipeline_results

def main():
    parser = argparse.ArgumentParser(description='CTF Encoding Cracker')
    parser.add_argument('text', nargs='?', help='Input string to crack')
    parser.add_argument('--show-all', action='store_true', help='Show all results in terminal')
    parser.add_argument('--output', default=None, help='Output filename')
    parser.add_argument('--list-methods', action='store_true', help='List all methods and exit')
    parser.add_argument('--only', default=None,
                        help='Comma-separated categories: base,rot,xor,classic,transpos,text,compress,tricks,hash,subst')
    parser.add_argument('--max-depth', type=int, default=MAX_PIPELINE_DEPTH,
                        help='Max pipeline depth (default: 3)')
    parser.add_argument('--no-parallel', action='store_true',
                        help='Disable parallel processing (default: parallel enabled)')
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
    print(_c(Fore.YELLOW if HAS_COLOR else '', f"[*] Pipeline max depth: {args.max_depth}"))
    if not args.no_parallel:
        print(_c(Fore.YELLOW if HAS_COLOR else '', f"[*] Parallel processing enabled"))
    else:
        print(_c(Fore.YELLOW if HAS_COLOR else '', "[*] Parallel processing disabled"))

    # Progress bar setup
    if HAS_TQDM:
        progress_bar = tqdm(
            total=len(methods) * args.max_depth,  # Total methods * max depth
            desc=_c(Fore.CYAN, f"Layer {1}"),
            unit="method",
            dynamic_ncols=True,  # Auto-resize to terminal width
            bar_format=_c(Fore.GREEN, '{l_bar}{bar}| ') + _c(Fore.YELLOW, '{n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]'),
            leave=True,  # Keep progress bar visible after completion
        )
    else:
        progress_bar = _Spinner(desc=_c(Fore.CYAN, f"Layer {1}"), total=len(methods) * args.max_depth)

    # Run pipeline
    results = run_pipeline(
        text, methods, max_depth=args.max_depth, parallel=not args.no_parallel,
        progress_bar=progress_bar,
    )
    if progress_bar:
        progress_bar.close()

    # Save to file
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs("results", exist_ok=True)
    output_path = args.output or os.path.join("results", f"results_{ts}.txt")
    reporter.save_results(results, text, output_path)

    # Print terminal summary
    reporter.print_summary(results, output_path, show_all=args.show_all)

if __name__ == '__main__':
    main()