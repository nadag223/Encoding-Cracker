"""Substitution cipher solvers: simple substitution, Caesar, etc."""

from utils.scorer import solve_substitution_cipher

def simple_substitution_solve(text: str) -> str | None:
    """Solve simple substitution cipher using hill-climbing/genetic algorithm."""
    try:
        return solve_substitution_cipher(text)
    except Exception:
        return None

def caesar_brute_force(text: str) -> str | None:
    """Brute-force all Caesar shifts (ROT0-25)."""
    try:
        best_result = None
        best_score = -float('inf')

        for shift in range(26):
            result = []
            for c in text:
                if c.isupper():
                    result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
                elif c.islower():
                    result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
                else:
                    result.append(c)
            result_str = ''.join(result)

            # Simple scoring: look for common words
            score = 0
            if 'THE' in result_str.upper():
                score += 5
            if 'AND' in result_str.upper():
                score += 3
            if 'ING' in result_str.upper():
                score += 2
            if 'ION' in result_str.upper():
                score += 2

            if score > best_score:
                best_score = score
                best_result = result_str

        return best_result
    except Exception:
        return None

def get_methods():
    return [
        ("Simple Substitution Solver", simple_substitution_solve),
        ("Caesar Brute Force (ROT0-25)", caesar_brute_force),
    ]