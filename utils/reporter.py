"""Handles writing the full results log to TXT and printing the terminal summary."""
import os
import sys
from datetime import datetime

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

def _c(color_code, text):
    """Wrap text in color if colorama is available."""
    if HAS_COLOR:
        return color_code + text + Style.RESET_ALL
    return text

def _safe_for_console(text: str) -> str:
    """Return ``text`` safely encodable to the active stdout encoding.

    On Windows the default console codec (e.g. cp1255) cannot represent many
    characters that appear in method names (Unicode arrows) or decoded results
    (e.g. high bytes from a noisy decode). Printing those verbatim raised
    UnicodeEncodeError and took the whole summary down. Sanitizing per-print is
    safer than reconfiguring stdout because reconfiguration can still fail
    silently and leave half a line printed.
    """
    if text is None:
        return ''
    enc = getattr(sys.stdout, 'encoding', None) or 'utf-8'
    try:
        text.encode(enc)
        return text
    except (UnicodeEncodeError, LookupError):
        return text.encode(enc, errors='replace').decode(enc, errors='replace')

def save_results(results: list, original: str, output_path: str):
    """Write all results sorted by score to a TXT file."""
    sorted_r = sorted(results, key=lambda x: x['score'], reverse=True)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    lines = []
    lines.append("=" * 64)
    lines.append("CTF ENCODING CRACKER — Full Results Log")
    lines.append(f"Input : {original}")
    lines.append(f"Run at: {now}")
    lines.append(f"Total attempts: {len(results)}")
    lines.append("=" * 64)
    lines.append("")

    for i, r in enumerate(sorted_r, 1):
        score = r['score']
        label = " ★★★ LIKELY CORRECT" if score >= 80 else (" ★★ POSSIBLE" if score >= 50 else "")
        lines.append(f"[{i:03d}] Score: {score}/100{label}")
        lines.append(f"Method : {r['method']}")
        result_preview = str(r['result'])[:300]
        lines.append(f"Result : {result_preview}")
        notes = ". ".join(r.get('notes', [])) or "No notes."
        lines.append(f"Notes  : {notes}")
        lines.append("-" * 64)

    lines.append("")
    lines.append("=" * 64)
    lines.append("END OF LOG — Review manually if no high-score result found")
    lines.append("=" * 64)

    with open(output_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write('\n'.join(lines))

def print_summary(results: list, output_path: str, show_all: bool = False):
    """Print top results to terminal."""
    sorted_r = sorted(results, key=lambda x: x['score'], reverse=True)
    positive = [r for r in sorted_r if r['score'] > 0]
    display = positive if show_all else positive[:10]

    print()
    print(_c(Fore.CYAN if HAS_COLOR else '', "TOP RESULTS:"))
    print("=" * 52)

    for i, r in enumerate(display, 1):
        score = r['score']
        method = _safe_for_console(r['method'][:20].ljust(20))
        result_str = _safe_for_console(str(r['result'])[:40].replace('\n', ' '))

        # score is a float in [0,100]; render with one decimal, width 5.
        if score >= 80:
            icon = "[OK]"
            score_str = f"{score:5.1f}/100"
        elif score >= 50:
            icon = "[!?]"
            score_str = f"{score:5.1f}/100"
        else:
            icon = " "
            score_str = f"{score:5.1f}/100"

        print(f" #{i:<2} [{score_str}] {method} -> {result_str}  {icon}")

    print("=" * 52)
    print(_safe_for_console(f"[+] Full log saved: {output_path}"))
    print(_safe_for_console(f"[+] Saved {len(results)} attempts to {os.path.basename(output_path)}"))
