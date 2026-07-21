"""Regression tests for the overhauled confidence scoring system.

These pin the exact bug report (a clean single-layer domain decode must outrank
multi-layer gibberish chains that produce lookalike-but-invalid domains) and the
inverse — that the structural detector no longer fires on punctation-heavy
gibberish while it correctly fires on fully valid multi-label domains.

Run directly:
    py tests/test_scoring.py
or with pytest:
    pytest tests/test_scoring.py
"""
import os
import sys
import time

# Make the project importable when run from anywhere.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from utils import detector, scorer
from utils.markov_language import naturalness


# ── Part 3: structural / domain detection regression anchors ─────────────────

def test_valid_multilabel_domain_matches():
    """goramli.bsmch.idf.il is a fully valid multi-label domain with a known TLD
    (.il) — it MUST set strong_structural_match. (Bug report false-negative.)"""
    sig = detector.get_structural_signals("goramli.bsmch.idf.il")
    assert sig["strong_structural_match"] == 1.0
    assert sig["valid_domain"] == 1.0
    assert detector.is_valid_domain("goramli.bsmch.idf.il") is True


def test_google_com_matches():
    assert detector.is_valid_domain("google.com") is True
    assert detector.get_structural_signals("google.com")["strong_structural_match"] == 1.0


def test_punctuation_gibberish_does_not_match():
    """The exact gibberish from the bug report MUST NOT match the domain regex.
    Its ``WT.MH`` looks dot-ish but the labels are invalid and there is no
    valid TLD. (Bug report false-positive — this was matching before.)"""
    gibberish = [
        "WT.MH#F(L]B7KI+N2?1^NF4II",
        "xu.ni#g(m]cIlj+oD?CogFjj",
        "MH.EN#B(L]D7SG+X2?1^XB4GG",
        "DA.TO#M(S]I7RP+U2?1^UM4PP",
        "AL.CD#T(X]Z7SI+H2?1^HT4II",
        "VS.LG#E(K]A7JH+M2?1^ME4HH",
        "OKMPHL.KKK",
        "TLLTOV.XLN",
        "xu.ni",
    ]
    for g in gibberish:
        assert detector.is_valid_domain(g) is False, (
            f"gibberish should not be a valid domain: {g!r}"
        )
        assert detector.get_structural_signals(g)["strong_structural_match"] == 0.0


def test_jet_matches_but_bare_dot_separated_letters_do_not():
    """A real JWT (three base64url segments) sets valid_jwt; a 1-char-segment
    ``a.b.c`` does NOT (segments too short)."""
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
           ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    assert detector.get_structural_signals(jwt)["valid_jwt"] == 1.0
    assert detector.get_structural_signals("a.b.c")["valid_jwt"] == 0.0


# ── Part 1/2: scoring formula and the language signal ───────────────────────

def test_correct_domain_outscores_gibberish_chain():
    """Reproduce the exact bug report:
    input  FCvkQ#c(U]h7p.+W2?1^Wc4RR
    correct goramli.bsmch.idf.il   (single-layer Base92 decode, valid domain)
    noise   WT.MH#F(L]B7KI+N2?1^NF4II  (2-3 layer gibberish chain)

    The correct answer must score strictly higher than every gibberish chain
    result, with a clear gap (90+ vs well under 50).
    """
    original = "FCvkQ#c(U]h7p.+W2?1^Wc4RR"
    correct = "goramli.bsmch.idf.il"
    gibberish_results = [
        ("WT.MH#F(L]B7KI+N2?1^NF4II", 3),
        ("xu.ni#g(m]cIlj+oD?CogFjj", 3),
        ("MH.EN#B(L]D7SG+X2?1^XB4GG", 3),
        ("AL.CD#T(X]Z7SI+H2?1^HT4II", 3),
        ("EH.OT#V(P]Z7QS+N2?1^NV4SS", 3),
        ("VS.LG#E(K]A7JH+M2?1^ME4HH", 3),
        ("DA.TO#M(S]I7RP+U2?1^UM4PP", 3),
    ]
    sc, _ = scorer.score(original, correct, pipeline_depth=1)
    assert sc >= 90.0, f"correct domain should score >=90, got {sc}"
    for g, depth in gibberish_results:
        sg, _ = scorer.score(original, g, pipeline_depth=depth)
        assert sg < 50.0, (
            f"gibberish {g!r} at depth {depth} scored {sg} (must be <50)"
        )
        assert sc > sg, (
            f"correct ({sc}) must outrank gibberish ({sg}): {g!r}"
        )


def test_google_com_from_base64_outscores_pipeline_gibberish():
    """A second real failing case from the run: google.com (single-layer Base64)
    must outrank any 2-layer domain-shaped or gibberish result."""
    original = "Z29vZ2xlLmNvbQ=="
    sc, _ = scorer.score(original, "google.com", pipeline_depth=1)
    assert sc >= 90.0
    # 2-layer uppercase domain-shaped noise (lucky Caesar/Affine shift producing
    # a structurally valid-looking but spurious domain) is damped by depth decay.
    sc_noise, _ = scorer.score(original, "OKMPHL.KKK", pipeline_depth=2)
    assert sc > sc_noise, f"google.com ({sc}) must outrank OKMPHL.KKK ({sc_noise})"
    # Pure 2-layer gibberish must be well under 50.
    sc_gib, _ = scorer.score(original, "TLLTOV.XLN", pipeline_depth=2)
    assert sc_gib < 50.0


def test_depth_decay_applied_per_layer():
    """Depth 1 incurs no penalty; each extra layer multiplies by 0.85."""
    original = "FCvkQ#c(U]h7p.+W2?1^Wc4RR"
    result = "goramli.bsmch.idf.il"  # strong structural match
    s1, _ = scorer.score(original, result, pipeline_depth=1)
    s2, _ = scorer.score(original, result, pipeline_depth=2)
    s3, _ = scorer.score(original, result, pipeline_depth=3)
    assert abs(s1 - 100.0) < 0.1
    assert abs(s2 - 85.0) < 0.1   # 100 * 0.85
    assert abs(s3 - 72.25) < 0.1  # 100 * 0.85**2


def test_signals_are_normalized():
    """Every signal feeding the formula must be in [0,1]."""
    samples = [
        "goramli.bsmch.idf.il",
        "google.com",
        "WT.MH#F(L]B7KI+N2?1^NF4II",
        "the quick brown fox jumps over the lazy dog",
        "",
        "!!!",
    ]
    for s in samples:
        sig, _ = scorer.compute_signals("x", s if s else " ")
        # core formula keys all in [0,1]
        for k in ("strong_structural_match", "ascii_ratio", "language_score",
                  "entropy_drop", "diff_from_input", "weak_pattern_bonus"):
            v = sig.get(k, 0.0)
            assert -1e-6 <= v <= 1.0 + 1e-6, f"{k}={v} out of [0,1] for {s!r}"


def test_markov_naturalness_real_english_high_gibberish_low():
    """The self-trained Markov model should rate real English high (>0.4) and
    random symbol/letter gibberish low (<0.15)."""
    assert naturalness("the quick brown fox jumps over the lazy dog") > 0.40
    assert naturalness("security through obscurity is not security at all") > 0.30
    assert naturalness("WT.MH#F(L]B7KI+N2?1^NF4II") < 0.15
    assert naturalness("TLLTOV.XLN") < 0.05


def test_subsitution_solver_still_importable():
    """The simple-substitution solver API (consumed by
    methods/substitution_ciphers.py) is preserved and returns a string."""
    from utils.scorer import solve_substitution_cipher
    # A short text returns None (too short to climb) — API contract preserved.
    assert solve_substitution_cipher("ab") is None


# ── Part 2 req #5: language signal gated behind a cheap pre-filter ─────────
# Guard that the language signal is NOT computed for low-printable input (so a
# full run does not pay wordfreq/Markov cost on thousands of raw byte-soup
# attempts). We profile a representative batch.

def test_language_signal_gated_by_printable_ratio():
    import re
    low_printable = "\x00\x01\x02\x03\x04\x05this is unprintable-ish"
    # printable_ratio for this is well below the gate.
    assert scorer.printable_ratio(low_printable) < scorer._PRINTABLE_GATE
    sig, _ = scorer.compute_signals("orig", low_printable)
    # When the pre-filter rejects, language_score must be 0 and the note must
    # say scoring was skipped (no wordfreq/Markov work performed).
    assert sig["language_score"] == 0.0


def test_full_run_runtime_budget(capsys=None):
    """Profile a representative scoring batch to confirm the language signal's
    gate keeps the cost down. Targets: a few thousand score() calls should
    complete in well under a few seconds; the expensive language pass is only
    run for printable, length-bounded candidates (per Part 2 req #5)."""
    import random
    random.seed(0)
    candidates = []
    base_words = ["goramli", "bsmch", "idf", "google", "com", "the", "flag",
                  "ctf", "hello", "world", "WT", "MH", "OKMPHL", "KKK"]
    for i in range(2000):
        k = random.randint(3, 24)
        candidates.append("".join(random.choice(base_words +
                                                  list("abcdef0123456789. "
                                                        "#?()[]^+")) for _ in range(k)))
    t0 = time.perf_counter()
    for c in candidates:
        scorer.score("FCvkQ#c(U]h7p.+W2?1^Wc4RR", c, pipeline_depth=1)
    dt = time.perf_counter() - t0
    print(f"\n[profile] 2000 score() calls in {dt:.3f}s "
          f"({dt/2000*1000:.3f} ms/call)")
    # Loose guard: 2000 calls must finish in a reasonable time on any modern
    # machine. The exact budget is machine-dependent; this just catches
    # catastrophic regressions (e.g. retraining the Markov model per call).
    assert dt < 30.0, f"scoring is too slow: {dt:.3f}s for 2000 calls"
    # And confirm the model is NOT retrained per call (LRU cache holds it).
    from utils.markov_language import get_model
    m1 = get_model()
    m2 = get_model()
    assert m1 is m2  # same cached object


# ── runner ───────────────────────────────────────────────────────────────────

def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
            failed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  ERR   {fn.__name__}: {type(e).__name__}: {e}")
            failed += 1
    # The profile test prints timing; run it explicitly too.
    try:
        test_full_run_runtime_budget()
        print(f"  PASS  test_full_run_runtime_budget")
        passed += 1
    except AssertionError as e:
        print(f"  FAIL  test_full_run_runtime_budget: {e}")
        failed += 1
    except Exception as e:  # noqa: BLE001
        print(f"  ERR   test_full_run_runtime_budget: {type(e).__name__}: {e}")
        failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(fns)+1} total")
    return failed == 0


if __name__ == "__main__":
    ok = _run()
    sys.exit(0 if ok else 1)
