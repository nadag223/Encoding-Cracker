"""Handles writing the full results log to TXT and printing the terminal summary."""
import os
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
        method = r['method'][:20].ljust(20)
        result_str = str(r['result'])[:40].replace('\n', ' ')

        if score >= 80:
            icon = "[OK]"
            score_str = f"{score:3d}/100"
        elif score >= 50:
            icon = "[!?]"
            score_str = f"{score:3d}/100"
        else:
            icon = " "
            score_str = f"{score:3d}/100"

        print(f" #{i:<2} [{score_str}] {method} -> {result_str}  {icon}")

    print("=" * 52)
    print(f"[+] Full log saved: {output_path}")
    print(f"[+] Saved {len(results)} attempts to {os.path.basename(output_path)}")
