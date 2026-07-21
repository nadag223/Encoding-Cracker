"""Confidence scoring for decoded candidates.

This overhaul replaces the old additive point table with a **normalized weighted
model**: every signal is a float in [0.0, 1.0] and combined via a weighted sum
(except for the dominant structural signal, which short-circuits to a high base).
A per-pipeline-layer decay then penalizes deep decode chains, so a clean
single-layer decode outranks a multi-layer chain that produces gibberish.

Layout
------
* Signal computation (each returns a normalized [0,1] value + an optional
  human-readable note): ``compute_signals(original, result)``.
* Aggregation / formula: ``compute_score(signals, pipeline_depth)``.
* Public entry used by ``cracker.py``: ``score(original, result, pipeline_depth)``.

The two layers are kept separate so new signals can be added in
``compute_signals`` without touching ``compute_score``.

Language-plausibility signal (the old n-gram scorer was unbounded and
inconsistent; it is gone): combines
  (a) ``wordfreq`` lexical frequency across many languages (offline, bundled
      tables), and
  (b) a self-trained 2-character Markov "naturalness" model
      (``utils.markov_language``), also offline.
The combination takes the max of the wordfreq lexical score and the Markov
naturalness score: a candidate that is valid human text in *one* of the two
senses (real dictionary words OR natural bigram statistics) should score
well, while something that fails both fails the signal. We use max rather than
mean because a domain like ``google.com`` reads as natural letters but its
labels are not always dictionary words — the Markov branch rescues it — whereas
``goramli.bsmch.idf.il`` is rescued by neither and correctly relies on the
structural signal instead.
"""
from __future__ import annotations

import math
import re
import string
import random
import heapq

from utils import detector
from utils.markov_language import naturalness as _markov_naturalness

# ── Hard pre-filter: only run the (relatively) expensive language signal on
# candidates that pass a cheap printable-ASCII gate, to keep a ~methods * layers
# run fast. See Part 2 requirement #5 / profilation target.
_PRINTABLE_GATE = 0.85
_MIN_LEN_FOR_LANGUAGE = 4


# ── Basic text statistics (kept; reused for several normalized signals) ──────

def printable_ratio(text: str) -> float:
    """Ratio of printable ASCII chars in the string (in [0,1])."""
    if not text:
        return 0.0
    printable = sum(1 for c in text if c in string.printable)
    return printable / len(text)


def entropy(text: str) -> float:
    """Shannon entropy of the string (in bits/char)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


CTF_FLAG_RE = re.compile(r'[A-Za-z0-9_\-]+\{.+\}')


# ── wordfreq (lazy, optional) ────────────────────────────────────────────────
# wordfreq ships its frequency data bundled, so import + lookup is offline. We
# import lazily so the tool still runs if a user has not installed wordfreq (the
# language signal then degrades gracefully to the Markov branch alone).

import functools as _functools

def _load_wordfreq():
    try:
        # wordfreq emits verbose stderr notes for languages without a tokenizer
        # (e.g. Thai) or for languages aliased to a nearest-match code
        # (e.g. Norwegian 'no' -> Bokmål 'nb'). Silence that chatter so it does
        # not pollute the cracker's output. We deliberately exclude such
        # languages from _WORDFREQ_LANGS below, but the filter is a belt-and-
        # braces guard against any future change to the import surface.
        import warnings
        warnings.filterwarnings('ignore')
        from wordfreq import zipf_frequency  # type: ignore
        import logging
        logging.getLogger('wordfreq').setLevel(logging.ERROR)
        return zipf_frequency
    except Exception:
        return None

_ZIPF = None  # the raw zipf_frequency callable, lazily resolved
# A curated subset of wordfreq's ~40 supported languages. Excluded:
#   * 'th' (Thai)  — no bundled tokenizer; prints "bad results" warnings.
#   * 'no' (Nor.) — alias-only; wordfreq remaps to 'nb' and prints a warning.
#   * 'ja','zh','ko' — require the optional MeCab/CJK tokenizer, which is a
#     heavy extra binary dependency and frequently absent. Excluding them keeps
#     the tool fully offline & crash-free. (Arabic/Greek/Hebrew/Cyrillic/Latin
#     scripts tokenize via the bundled regex, no MeCab needed.) The task's
#     named base languages (English, Spanish, Hebrew) are all included.
_WORDFREQ_LANGS = (
    'en', 'es', 'he', 'de', 'fr', 'pt', 'it', 'nl', 'ru', 'pl', 'tr',
    'id', 'vi', 'cs', 'sv', 'fi', 'da', 'uk', 'ro', 'hu', 'el', 'ar',
)
# Per-token zipf lookup is memoized: a full cracker run touches the same words
# many times across candidates and across the multi-language loop, so caching
# ``zipf_frequency(token, lang)`` collapses the dominant cost. wordfreq already
# maintains an internal dict cache, but ours also survives across the curried
# partials and short-circuits. This is the single biggest lever for hitting the
# Part 2 runtime budget.
@_functools.lru_cache(maxsize=131072)
def _zipf_cached(token: str, lang: str) -> float:
    """Memoized zipf_frequency lookup; returns -1.0 on any error (treated as
    'not a frequent word' by the caller)."""
    global _ZIPF
    if _ZIPF is None:
        _ZIPF = _load_wordfreq()
    if _ZIPF is None:
        return -1.0
    try:
        return float(_ZIPF(token, lang))
    except Exception:
        return -1.0


# zipf_frequency of >= 3.0 corresponds roughly to a word used in ~1-in-10k or
# more frequent English usage — a reasonable "this is a real word" cutoff.
_ZIPF_WORD_THRESHOLD = 3.0
# Short tokens (length 2) are real words/abbreviations in *some* language among
# the dozens wordfreq supports (e.g. "ki" in Turkish, "ii" in Polish, "mh" in
# Indonesian). Scanning all languages for 2-letter gibberish therefore produces
# near-universal false positives and makes wordfreq useless as a signal. We
# therefore only score tokens of length >= 3 with wordfreq, leaving short-noise
# detection to the Markov naturalness branch.
_WORDFREQ_MIN_TOKEN_LEN = 3
# Require at least this many scorable tokens for the wordfreq score to be
# meaningful at all — a single hit on one long-ish token is weak evidence.
_WORDFREQ_MIN_TOKENS = 2


def _wordfreq_lexical_score(text: str) -> float:
    """Fraction of alphabetic tokens (len>=3) in ``text`` that are reasonably
    frequent words in *some* supported language. Returns [0,1].

    Takes the best-scoring language. Degradation: if wordfreq is not installed,
    returns -1.0 so the caller can fall back entirely to the Markov branch and
    this remains a fully offline, dependency-optional tool.

    Performance: per-token zipf lookups are memoized (``_zipf_cached``) and the
    multi-language loop short-circuits once any language reaches a strong
    fraction. Without memoization this call scanned 25 languages × N tokens and
    dominated a full run; with these two measures it is a small minority of the
    runtime, satisfying the Part 2 runtime budget.

    Tokens shorter than 3 chars are excluded: across wordfreq's ~40 supported
    languages almost every 2-letter string is a real word elsewhere, which made
    the old loop label noise like ``WT.MH#F(L]B7KI+N2?1^NF4II`` "plausible" in
    Turkish/Polish/Indonesian by accident. Detecting short-noise is the Markov
    naturalness branch's job."""
    global _ZIPF
    if _ZIPF is None:
        _ZIPF = _load_wordfreq()
    if _ZIPF is None:
        return -1.0

    tokens = [w for w in re.findall(r'[^\W\d_]{2,}', text.lower())]
    if not tokens:
        return 0.0

    # Common (sub)domain/URL/protocol artifacts that wordfreq won't know about
    # are "neutral"—not good words but not evidence against a plausible-text
    # result either. We exclude them from both numerator and denominator so a
    # clean URL does not tank its own lexical score.
    structural_noise = {
        'com', 'org', 'net', 'io', 'co', 'gov', 'edu', 'www', 'http', 'https',
        'html', 'xml', 'json', 'php', 'asp', 'jsp', 'css',
    }
    scored = [
        t for t in tokens
        if t not in structural_noise and len(t) >= _WORDFREQ_MIN_TOKEN_LEN
    ]
    if len(scored) < _WORDFREQ_MIN_TOKENS:
        # Too few long tokens to make a lexical judgement; defer to Markov.
        return 0.0

    best = 0.0
    # Short-circuit threshold: once any language already labels >=80% of tokens
    # as frequent words, further languages cannot raise the (already strong)
    # signal meaningfully — stop and move on.
    _STOP_AT = 0.80

    # Tiered evaluation: the overwhelming majority of scorable CTF candidates
    # are English (or English-shaped). Scoring English first and moving on to
    # the other ~20 languages *only* when English is weak avoids paying the
    # full multi-language cost on every candidate — the dominant runtime lever.
    _PRIMARY_LANGS = ('en', 'es', 'he', 'de', 'fr')
    _SECONDARY_LANGS = tuple(l for l in _WORDFREQ_LANGS if l not in _PRIMARY_LANGS)

    for lang in _PRIMARY_LANGS:
        hits = sum(1 for tok in scored if _zipf_cached(tok, lang) >= _ZIPF_WORD_THRESHOLD)
        frac = hits / len(scored)
        if frac > best:
            best = frac
            if best >= _STOP_AT:
                return round(best, 4)

    # Only pay for the full language sweep when no primary language already
    # explained the tokens (i.e. the candidate probably isn't common-language
    # prose and might be a rarer language, or it's just noise — in which case
    # best stays 0 and the caller relies on the Markov branch anyway).
    if best >= 0.1:
        return round(best, 4)

    for lang in _SECONDARY_LANGS:
        hits = sum(1 for tok in scored if _zipf_cached(tok, lang) >= _ZIPF_WORD_THRESHOLD)
        frac = hits / len(scored)
        if frac > best:
            best = frac
            if best >= _STOP_AT:
                break
    return round(best, 4)


# ── Composite language signal ────────────────────────────────────────────────

def language_score(text: str) -> tuple[float, str]:
    """Return (normalized language/plausibility score in [0,1], note).

    Combines (via max) a wordfreq lexical score and the Markov naturalness
    score. See module docstring for the max-vs-mean rationale."""
    if not text or len(text.strip()) < _MIN_LEN_FOR_LANGUAGE:
        return 0.0, "too short for language scoring"

    wf = _wordfreq_lexical_score(text)
    markov = _markov_naturalness(text)

    if wf < 0.0:
        # wordfreq unavailable — fully degrade to Markov only.
        combined = markov
        note = f"language=markov-only ({markov:.2f})"
    else:
        combined = max(wf, markov)
        note = f"language wordfreq={wf:.2f} markov={markov:.2f} (max={combined:.2f})"
    return round(min(1.0, max(0.0, combined)), 4), note


# ── Signal computation ───────────────────────────────────────────────────────

def _ascii_ratio_signal(result: str) -> float:
    """Normalized printable-ASCII ratio in [0,1]."""
    return round(min(1.0, max(0.0, printable_ratio(result))), 4)


def _entropy_drop_signal(original: str, result: str) -> float:
    """Normalized entropy-drop in [0,1]. 0 = entropy did not drop (or rose);
    1 = entropy dropped a lot relative to the input. We map the raw drop (in
    bits/char, input - result) through a saturating ramp: a drop of ~1.5 bits
    already counts as "significant", ~3 bits as maximal."""
    if not original or not result:
        return 0.0
    e_in = entropy(original)
    e_out = entropy(result)
    if e_in <= 0:
        return 0.0
    diff = e_in - e_out
    if diff <= 0:
        return 0.0
    # saturating ramp: ~1.5 bits -> ~0.5, ~3 bits -> ~0.95
    sat = diff / (diff + 1.5)
    return round(min(1.0, sat), 4)


def _diff_from_input_signal(original: str, result: str) -> float:
    """How unlike the input the decoded result is, in [0,1].

    A genuine decode almost always differs from the input on most bytes (an
    Encoder→decoder round-trip would collapse to the input, but the cracker
    skips identical outputs already at the top level; nested results, however,
    can transitively become near-identical to an *intermediate*). We use a
    character-level normalized edit distance proxy: fraction of positions where
    the (extended) two strings differ. Length differences also count against
    similarity."""
    a, b = original, result
    n = max(len(a), len(b))
    if n == 0:
        return 1.0
    same = 0
    for i in range(n):
        ca = a[i] if i < len(a) else None
        cb = b[i] if i < len(b) else None
        if ca == cb:
            same += 1
    return round(1.0 - same / n, 4)


def _weak_pattern_bonus_signal(result: str) -> tuple[float, list[str]]:
    """Small, *capped* bonus signal in [0,1] from lightweight patterns: a CTF
    flag template, or a recognizable file/content shape (JSON / HTML / URL)."""
    bonuses = []
    notes: list[str] = []

    if CTF_FLAG_RE.search(result):
        bonuses.append(0.5)
        notes.append("Matched CTF flag pattern.")

    stripped = result.strip()
    if stripped.startswith('{') and stripped.endswith('}') and '"' in stripped:
        bonuses.append(0.25)
        notes.append("Looks like JSON content.")
    if '<' in stripped and '>' in stripped and (
        '<html' in stripped.lower() or '<?xml' in stripped.lower()
    ):
        bonuses.append(0.25)
        notes.append("Looks like HTML/XML content.")

    return round(min(1.0, sum(bonuses)), 4), notes


def compute_signals(original: str, result: str) -> tuple[dict, list[str]]:
    """Compute all normalized [0,1] signals for ``(original, result)`` and a
    list of human-readable notes. Returns ``(signals, notes)``.

    This is the ONLY place signals are computed; ``compute_score`` only aggregates.
    """
    notes: list[str] = []

    # Structural signal — dominant short-circuit. Only the precise detectors in
    # detector.py set this (never the loose pattern heuristics below).
    struct = detector.get_structural_signals(result)
    strong = struct['strong_structural_match']
    if strong >= 1.0:
        if struct['valid_domain']:
            notes.append("Valid domain structure (labels + known TLD).")
        elif struct['valid_jwt']:
            notes.append("Valid JWT structure.")
        elif struct['valid_pem']:
            notes.append("Valid PEM block.")
        elif struct['valid_magic']:
            notes.append("Recognized file-format magic bytes.")

    ascii_ratio = _ascii_ratio_signal(result)

    # Language signal — gated behind a cheap printable-ASCII + length check so
    # the (relatively) expensive wordfreq/Markov pass only runs on plausible
    # candidates, not all raw attempts.
    if printable_ratio(result) >= _PRINTABLE_GATE and len(result.strip()) >= _MIN_LEN_FOR_LANGUAGE:
        lang, lang_note = language_score(result)
    else:
        lang = 0.0
        lang_note = "language scoring skipped (low printable ratio)"
    notes.append(lang_note)

    entropy_drop = _entropy_drop_signal(original, result)
    notes.append(f"entropy_drop={entropy_drop:.2f}")

    diff_from_input = _diff_from_input_signal(original, result)
    notes.append(f"diff_from_input={diff_from_input:.2f}")

    weak_bonus, weak_notes = _weak_pattern_bonus_signal(result)
    notes.extend(weak_notes)

    signals = {
        'strong_structural_match': strong,
        'ascii_ratio': ascii_ratio,
        'language_score': lang,
        'entropy_drop': entropy_drop,
        'diff_from_input': diff_from_input,
        'weak_pattern_bonus': weak_bonus,
        # Pass-throughs for telemetry / notes only (not in the main formula):
        'pipeline_depth': 1,  # default; overridden by caller
    }
    return signals, notes


# ── Aggregation / formula (Part 1) ───────────────────────────────────────────

def compute_score(signals: dict, pipeline_depth: int) -> float:
    """Aggregate normalized signals + pipeline depth into a 0-100 score.

    Structure mirrors the Part 1 spec:

        if strong_structural_match:            # dominant
            base = 0.90 + 0.10 * ascii_ratio
        else:
            base = 0.30*ascii_ratio + 0.25*language_score
                  + 0.20*entropy_drop + 0.15*diff_from_input
                  + 0.10*weak_pattern_bonus
        decay = 0.85 ** max(0, pipeline_depth - 1)   # no penalty at depth 1
        return round(base * decay * 100, 1)
    """
    if signals.get('strong_structural_match', 0.0) >= 1.0:
        base = 0.90 + 0.10 * signals.get('ascii_ratio', 0.0)
    else:
        base = (
            0.30 * signals.get('ascii_ratio', 0.0)
            + 0.25 * signals.get('language_score', 0.0)
            + 0.20 * signals.get('entropy_drop', 0.0)
            + 0.15 * signals.get('diff_from_input', 0.0)
            + 0.10 * signals.get('weak_pattern_bonus', 0.0)
        )

    decay = 0.85 ** max(0, pipeline_depth - 1)   # no penalty for depth == 1
    return round(base * decay * 100, 1)


# ── Public entry point (used by cracker.py) ──────────────────────────────────

def score(original: str, result: str, pipeline_depth: int = 1) -> tuple[float, list[str]]:
    """Return ``(score in [0,100], notes)`` for a decoded ``result`` of ``original``.

    Identical / empty outputs are skipped with a fixed sentinel so callers can
    drop them (matches the pre-overhaul contract: a -99 sentinel).
    """
    notes: list[str] = []
    if not result:
        return -99.0, ["Output empty — skipped"]
    if result.strip() == original.strip():
        return -99.0, ["Output identical to input — skipped"]

    signals, notes = compute_signals(original, str(result))
    signals['pipeline_depth'] = pipeline_depth
    final = compute_score(signals, pipeline_depth)

    notes.append(f"ascii_ratio={signals['ascii_ratio']:.2f}")
    if signals['strong_structural_match'] >= 1.0:
        notes.append(f"strong_structural_match=1.0 pipeline_depth={pipeline_depth} "
                     f"decay={0.85 ** max(0, pipeline_depth - 1):.3f}")
    else:
        notes.append(f"weak_pattern_bonus={signals['weak_pattern_bonus']:.2f} "
                      f"pipeline_depth={pipeline_depth} "
                      f"decay={0.85 ** max(0, pipeline_depth - 1):.3f}")
    return final, notes


# ── Simple substitution cipher solver (fitness via Markov naturalness) ───────
# The old n-gram tables and ``_ngram_score`` are removed. ``solve_substitution_cipher``
# now hill-climbs against ``avg_logprob`` of the self-trained Markov model, which
# is a strictly better, bounded fitness function and reuses the same offline
# model the scorer uses.

from utils.markov_language import avg_logprob as _markov_avg_logprob


def _generate_random_key() -> dict[str, str]:
    """Generate random substitution key."""
    alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    shuffled = alphabet.copy()
    random.shuffle(shuffled)
    return {a: s for a, s in zip(alphabet, shuffled)}


def _apply_key(text: str, key: dict[str, str]) -> str:
    """Apply substitution key to uppercase-only text."""
    out = []
    for c in text.upper():
        out.append(key.get(c, c))
    return ''.join(out)


def _score_key_fitness(text: str, key: dict[str, str]) -> float:
    """Fitness of a candidate substitution key: higher avg-logprob = more
    English-like under the Markov model. We negate because avg_logprob is
    negative; maximizing -avg_logprob is the same as minimizing surprise."""
    decrypted = _apply_key(text, key)
    return -_markov_avg_logprob(decrypted)


def _mutate_key(key: dict[str, str]) -> dict[str, str]:
    """Mutate a substitution key by swapping two letters."""
    new_key = key.copy()
    a, b = random.sample(list(key.keys()), 2)
    new_key[a], new_key[b] = new_key[b], new_key[a]
    return new_key


def _hill_climb_substitution(text: str, max_iter: int = 1000) -> str | None:
    """Solve simple substitution cipher using hill-climbing on Markov fitness."""
    # Clean text: keep only letters (cipher text is usually uppercase alpha).
    clean_text = ''.join(c for c in text if c.isalpha())
    if len(clean_text) < 10:
        return None

    current_key = _generate_random_key()
    current_score = _score_key_fitness(clean_text, current_key)

    for _ in range(max_iter):
        new_key = _mutate_key(current_key)
        new_score = _score_key_fitness(clean_text, new_key)
        if new_score > current_score:
            current_key = new_key
            current_score = new_score

    return _apply_key(text, current_key)


def _genetic_substitution(text: str, pop_size: int = 100, max_gen: int = 50) -> str | None:
    """Solve simple substitution cipher using a genetic algorithm."""
    clean_text = ''.join(c for c in text if c.isalpha())
    if len(clean_text) < 10:
        return None

    population = [_generate_random_key() for _ in range(pop_size)]
    scores = [_score_key_fitness(clean_text, k) for k in population]

    for _ in range(max_gen):
        elite_size = max(5, pop_size // 5)
        elite = heapq.nlargest(elite_size, zip(scores, population), key=lambda x: x[0])
        elite_keys = [k for _, k in elite]
        new_population = elite_keys.copy()
        while len(new_population) < pop_size:
            parent1, parent2 = random.sample(elite_keys, 2)
            child = {}
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if random.random() < 0.5:
                    child[c] = parent1[c]
                else:
                    child[c] = parent2[c]
            # Repair: ensure all letters are present exactly once.
            used = set(child.values())
            missing = [c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c not in used]
            seen = {}
            repaired = {}
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                v = child[c]
                if v in seen or v not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    repaired[c] = missing.pop()
                else:
                    seen[v] = c
                    repaired[c] = v
            new_population.append(repaired)

        for i in range(elite_size, len(new_population)):
            if random.random() < 0.3:
                new_population[i] = _mutate_key(new_population[i])

        population = new_population
        scores = [_score_key_fitness(clean_text, k) for k in population]

    best_idx = scores.index(max(scores))
    return _apply_key(text, population[best_idx])


def solve_substitution_cipher(text: str) -> str | None:
    """Try to solve simple substitution cipher using multiple methods.

    Returns the best plaintext under the Markov fitness model, or None if the
    text is too short to hill-climb meaningfully."""
    try:
        result = _hill_climb_substitution(text, max_iter=500)
        if result is not None:
            return result
        return _genetic_substitution(text, pop_size=50, max_gen=30)
    except Exception:
        return None
