"""Offline Markov-chain "naturalness" / gibberish detector.

This is a self-trained 2-character Markov language model. We build it ourselves
rather than pulling in the (unmaintained) ``gibberish-detector`` PyPI package,
which is a thin wrapper around exactly the technique implemented here.

Design
------
* Train once, offline, from a bundled English text corpus
  (``wordlists/corpus_en.txt``).
* Persist the trained model to ``wordlists/markov_model.json`` so it is computed
  once, not retrained on every run.
* At scoring time, compute a normalized naturalness score in [0.0, 1.0] from
  the transition log-probabilities of the candidate string.

Fully offline: no network calls anywhere on this code path. ``wordfreq`` (used by
the scorer, not here) ships its frequency tables bundled too, so the language
plausibility signal as a whole stays offline.

Score interpretation
---------------------
We average the per-character log-prob of each observed bigram under the trained
model, with Laplace smoothing for unseen bigrams. A higher (less negative)
average log-prob means the text's character transitions look more like the
training corpus. We normalize to [0, 1] by squashing with a logistic curve
calibrated against a couple of reference points:

    avg_logprob  ~ -1.0  -> ~0.974  (very natural English; e.g. real sentences)
    avg_logprob  ~ -2.5  -> ~0.30   (mixed letter gibberish)
    avg_logprob  ~ -5.0  -> ~0.005  (random symbols / clearly not text)

This gives a smooth, comparable 0-1 naturalness score for the scoring formula.
"""
from __future__ import annotations

import json
import math
import os
import string
from functools import lru_cache

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
CORPUS_PATH = os.path.join(_PROJECT_ROOT, 'wordlists', 'corpus_en.txt')
MODEL_PATH = os.path.join(_PROJECT_ROOT, 'wordlists', 'markov_model.json')

# The model is trained on lowercase letters only (the common case across the
# corpus). Punctuation, digits, whitespace and other symbols are kept in the
# text stream while training so transitions across them shape the model, but
# we normalize candidate strings to lowercase before scoring so case does not
# confound the probabilty. This alpha table is the vocabulary used for
# smoothing below.
_ALPHA = string.ascii_lowercase + ' '

# Laplace (add-one) smoothing counts added for the bigram table, calibrated so
# that genuinely unseen English-y bigrams are penalized but not infinitely.
_SMOOTHING = 0.5


def _char_stream(text: str) -> str:
    """Normalize text for the Markov model: lowercase, collapse all runs of
    non-letter/whitespace characters to a single space, keep letters+spaces.
    This means punctuation-heavy gibberish collapses toward sparse symbol runs
    that the model scores as very unnatural."""
    out = []
    prev_space = False
    for ch in text.lower():
        if ch.isalpha() or ch == ' ':
            out.append(ch)
            prev_space = (ch == ' ')
        else:
            # Map punctuation/digits to a single space separator.
            if not prev_space:
                out.append(' ')
                prev_space = True
    return ''.join(out)


def train_model(corpus_path: str = CORPUS_PATH) -> dict:
    """Train a 2-character Markov model from the corpus and return the model dict.

    The model stores:
      * ``transitions``: {first_char: {second_char: count}}
      * ``row_totals``  : {first_char: total_count}
      * ``vocab``       : sorted list of characters seen (unigram vocabulary)
      * ``V``           : smoothing vocabulary size (= len(vocab), used for
        Laplace smoothing of unseen second-chars)

    Returned dict is JSON-serializable.
    """
    stream_lines = []
    with open(corpus_path, 'r', encoding='utf-8') as f:
        for line in f:
            s = _char_stream(line.strip('\n'))
            if s:
                stream_lines.append(s)
    stream = ' '.join(stream_lines)

    transitions: dict[str, dict[str, float]] = {}
    row_totals: dict[str, float] = {}
    vocab: set[str] = set()

    for i in range(len(stream) - 1):
        a, b = stream[i], stream[i + 1]
        vocab.add(a)
        vocab.add(b)
        row = transitions.setdefault(a, {})
        row[b] = row.get(b, 0.0) + 1.0
        row_totals[a] = row_totals.get(a, 0.0) + 1.0

    if not transitions or not stream:
        raise ValueError(f"Corpus at {corpus_path} produced an empty model.")

    return {
        'transitions': transitions,
        'row_totals': row_totals,
        'vocab': sorted(vocab),
        # Laplace smoothing denominator baseline: number of observed unique
        # second-characters anywhere (caps unseen bigram penalty sensibly).
        'V': len(vocab) if vocab else 1,
    }


def build_and_save(corpus_path: str = CORPUS_PATH, model_path: str = MODEL_PATH) -> dict:
    """Train the model and persist it to ``model_path`` as JSON. Returns the model."""
    model = train_model(corpus_path)
    # JSON keys must be strings; transitions are nested char dicts which
    # serialize fine (single chars become string keys).
    with open(model_path, 'w', encoding='utf-8') as f:
        json.dump(model, f, ensure_ascii=True)
    return model


def _load_model() -> dict:
    """Load the persisted model, training+saving it on first use if missing."""
    if not os.path.exists(MODEL_PATH):
        build_and_save()
    with open(MODEL_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


@lru_cache(maxsize=1)
def get_model() -> dict:
    """Return the loaded Markov model (cached for the process lifetime)."""
    return _load_model()


# ── Scoring ──────────────────────────────────────────────────────────────────

# Logistic squash parameters for average-log-prob -> [0,1] naturalness.
# Chosen so real English text lands in the 0.9-1.0 band and random letters
# / symbols collapse toward 0.
#
#  sigmoid(k * (x - x0))   where  x = avg_logprob
#   k  = 2.0, x0 = -2.3
#     x = -1.0  -> 0.974
#     x = -2.3  -> 0.5
#     x = -3.5  -> 0.197
#     x = -5.0  -> 0.040
_K = 2.0
_X0 = -2.3


def avg_logprob(text: str, model: dict | None = None) -> float:
    """Mean per-character log-probability of ``text`` under the model.

    Uses Laplace smoothing of ``_SMOOTHING`` over a vocab of size ``V`` for
    observed-but-unseen bigrams, and a floor for completely unknown first-char
    rows. Returns a float; higher (closer to 0) is more natural. Empty or
    all-symbol text returns a strongly negative sentinel.
    """
    if not text:
        return -8.0
    s = _char_stream(text)
    # Strip leading/trailing spaces; they carry little signal.
    s = s.strip()
    if len(s) < 2:
        return -8.0

    if model is None:
        model = get_model()
    transitions = model['transitions']
    row_totals = model['row_totals']
    V = model.get('V', len(model.get('vocab', _ALPHA))) or len(_ALPHA)

    total = 0.0
    n = 0
    for i in range(len(s) - 1):
        a, b = s[i], s[i + 1]
        row = transitions.get(a)
        denom = row_totals.get(a, 0.0)
        if row is None or denom == 0:
            # First char never seen in training: treat as maximally surprising.
            count = 0.0
            denom = 1.0
        else:
            count = row.get(b, 0.0)
        # Laplace-smoothed probability for the transition a -> b.
        p = (count + _SMOOTHING) / (denom + _SMOOTHING * V)
        total += math.log(max(p, 1e-12))
        n += 1
    return total / max(n, 1)


def naturalness(text: str, model: dict | None = None) -> float:
    """Normalized naturalness score in [0.0, 1.0].

    Squashes ``avg_logprob`` through a logistic curve calibrated against English
    text (see module docstring). Strings with no scorable letters/space collapse
    to ~0.
    """
    if not text:
        return 0.0
    x = avg_logprob(text, model)
    z = _K * (x - _X0)
    # numerically stable sigmoid
    if z >= 0:
        sig = 1.0 / (1.0 + math.exp(-z))
    else:
        ez = math.exp(z)
        sig = ez / (1.0 + ez)
    return round(max(0.0, min(1.0, sig)), 4)
