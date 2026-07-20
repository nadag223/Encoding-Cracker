"""Confidence scoring: rates how likely a decoded result is correct."""
import math
import re
import string
import random
import heapq
from collections import Counter

# ~500 common English words (offline, no NLTK needed)
ENGLISH_WORDS = {
    "the","be","to","of","and","a","in","that","have","it","for","not","on","with",
    "he","as","you","do","at","this","but","his","by","from","they","we","say","her",
    "she","or","an","will","my","one","all","would","there","their","what","so","up",
    "out","if","about","who","get","which","go","me","when","make","can","like","time",
    "no","just","him","know","take","people","into","year","your","good","some","could",
    "them","see","other","than","then","now","look","only","come","its","over","think",
    "also","back","after","use","two","how","our","work","first","well","way","even",
    "new","want","because","any","these","give","day","most","us","great","between",
    "need","large","often","hand","high","place","hold","turn","without","follow","act",
    "why","ask","men","change","went","light","kind","off","need","house","picture",
    "try","again","animal","point","mother","world","near","build","self","earth","father",
    "head","stand","own","page","found","answer","school","grow","study","still","learn",
    "plant","cover","food","sun","four","between","state","keep","eye","never","last",
    "let","thought","city","tree","cross","farm","hard","start","might","story","saw",
    "far","sea","draw","left","late","run","dont","while","press","close","night","real",
    "life","few","north","open","seem","together","next","white","children","begin","got",
    "walk","example","ease","paper","group","always","music","those","both","mark","book",
    "letter","until","mile","river","car","feet","care","second","enough","plain","girl",
    "usual","young","ready","above","ever","red","list","though","feel","talk","bird",
    "soon","body","dog","family","direct","pose","leave","song","measure","door","product",
    "black","short","numeral","class","wind","question","happen","complete","ship","area",
    "half","rock","order","fire","south","problem","piece","told","knew","pass","since",
    "top","whole","king","space","heard","best","hour","better","true","during","hundred",
    "five","remember","step","early","hold","west","ground","interest","reach","fast",
    "verb","sing","listen","six","table","travel","less","morning","ten","simple","several",
    "vowel","toward","war","lay","against","pattern","slow","center","love","person","money",
    "serve","appear","road","map","rain","rule","govern","pull","cold","notice","voice",
    "fall","power","town","fine","drive","lead","cry","dark","machine","note","wait","plan",
    "figure","star","box","noun","field","rest","correct","able","pound","done","beauty",
    "drive","stood","contain","front","teach","week","final","gave","green","oh","quick",
    "develop","ocean","warm","free","minute","strong","special","mind","behind","clear",
    "tail","produce","fact","street","inch","lot","nothing","course","stay","wheel","full",
    "force","blue","object","decide","surface","deep","moon","island","foot","system","busy",
    "test","record","boat","common","gold","possible","plane","stead","dry","wonder","laugh",
    "thousand","ago","ran","check","game","shape","equate","miss","brought","heat","snow",
    "tire","bring","yes","distant","fill","east","paint","language","among","grand","ball",
    "yet","wave","drop","heart","am","present","heavy","dance","engine","position","arm",
    "wide","sail","material","size","vary","settle","speak","weight","general","ice","matter",
    "circle","pair","include","divide","syllable","felt","perhaps","pick","sudden","count",
    "square","reason","length","represent","art","subject","region","energy","hunt","probable",
    "bed","brother","egg","ride","cell","believe","fraction","forest","sit","race","window",
    "store","summer","train","sleep","prove","lone","leg","exercise","wall","catch","mount",
    "wish","sky","board","joy","winter","sat","written","wild","instrument","kept","glass",
    "grass","cow","job","edge","sign","visit","past","soft","fun","bright","gas","weather",
    "month","million","bear","finish","happy","hope","flower","clothe","strange","gone",
    "jump","baby","eight","village","meet","root","buy","raise","solve","metal","whether",
    "push","seven","paragraph","third","shall","held","hair","describe","cook","floor","either",
    "result","burn","hill","safe","cat","century","consider","type","law","bit","coast",
    "copy","phrase","silent","tall","sand","soil","roll","temperature","finger","industry",
    "value","fight","lie","beat","excite","natural","view","sense","ear","else","quite",
    "broke","case","middle","kill","son","lake","moment","scale","loud","spring","observe",
    "child","straight","consonant","nation","dictionary","milk","speed","method","organ",
    "pay","age","section","dress","cloud","surprise","quiet","stone","small","climb","cool",
    "design","poor","lot","experiment","bottom","key","iron","single","stick","flat","twenty",
    "skin","smile","crease","hole","trade","melody","trip","office","receive","row","mouth",
    "exact","symbol","die","least","trouble","shout","except","wrote","seed","tone","join",
    "suggest","clean","break","lady","yard","rise","bad","blow","oil","blood","touch","grew",
    "cent","mix","team","wire","cost","lost","brown","wear","garden","equal","sent","choose",
    "fell","fit","flow","fair","bank","collect","save","control","decimal","gentle","woman",
    "captain","practice","separate","difficult","doctor","please","protect","noon","whose",
    "locate","ring","character","insect","caught","period","indicate","radio","spoke","atom",
    "human","history","effect","electric","expect","crop","modern","element","hit","student",
    "corner","party","supply","bone","rail","imagine","provide","agree","thus","capital",
    "chairs","whether","master","ready","science","list","map","find","long","use","place",
    "flag","ctf","challenge","hack","crypto","cyber","security","binary","encode","decode",
    "cipher","password","secret","hidden","message","solve","answer","level","game","puzzle"
}

def printable_ratio(text: str) -> float:
    """Ratio of printable ASCII chars in the string."""
    if not text:
        return 0.0
    printable = sum(1 for c in text if c in string.printable)
    return printable / len(text)

def entropy(text: str) -> float:
    """Shannon entropy of the string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

CTF_FLAG_RE = re.compile(r'[A-Za-z0-9_\-]+\{.+\}')

def score(original: str, result: str) -> tuple[int, list[str]]:
    """Return (score, notes_list) for a decoded result."""
    notes = []

    # Skip identical / empty
    if not result or result.strip() == original.strip():
        return -99, ["Output identical to input — skipped"]

    total = 0

    # +10 base: not empty and not identical
    total += 10
    notes.append("Output differs from input.")

    # +30 printable ASCII
    pr = printable_ratio(result)
    if pr > 0.85:
        total += 30
        notes.append(f"High printable ASCII ratio ({pr:.0%}).")

    # +25 CTF flag pattern
    if CTF_FLAG_RE.search(result):
        total += 25
        notes.append("Matched CTF flag pattern.")

    # +30 High-value domain patterns
    domain_patterns = [
        r'[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}',  # general domain
        r'google\.com', r'facebook\.com', r'amazon\.com', r'microsoft\.com',
        r'github\.com', r'youtube\.com', r'twitter\.com', r'linkedin\.com'
    ]
    for pattern in domain_patterns:
        if re.search(pattern, result.lower()):
            total += 30
            notes.append("Matched high-value domain pattern.")
            break  # Only add once

    # +20 English words
    words = re.findall(r'[a-zA-Z]{3,}', result.lower())
    if words:
        hits = sum(1 for w in words if w in ENGLISH_WORDS)
        if hits / len(words) > 0.2:
            total += 20
            notes.append(f"Contains common English words ({hits}/{len(words)}).")

    # +15 lower entropy than input
    if entropy(result) < entropy(original):
        total += 15
        notes.append("Lower entropy than input.")

    return min(total, 100), notes

# ── N-gram frequency tables for multiple languages ────────────────────────────

# English n-grams (log probabilities)
EN_NGRAMS = {
    'TH': 1.52, 'HE': 1.28, 'IN': 1.04, 'ER': 0.94, 'AN': 0.82,
    'RE': 0.78, 'ON': 0.75, 'AT': 0.71, 'EN': 0.68, 'ND': 0.63,
    'TI': 0.62, 'ES': 0.61, 'OR': 0.61, 'TE': 0.60, 'OF': 0.59,
    'ED': 0.58, 'IS': 0.53, 'IT': 0.50, 'AL': 0.49, 'AR': 0.49,
    'ST': 0.48, 'TO': 0.47, 'NT': 0.47, 'NG': 0.46, 'SE': 0.44,
    'HA': 0.43, 'OU': 0.43, 'AS': 0.42, 'IO': 0.42, 'LE': 0.41,
    'VE': 0.40, 'CO': 0.40, 'ME': 0.40, 'DE': 0.38, 'HI': 0.38,
    'RI': 0.37, 'RO': 0.37, 'IC': 0.36, 'NE': 0.36, 'EA': 0.35,
    'RA': 0.35, 'CE': 0.34, 'LI': 0.34, 'CH': 0.34, 'LL': 0.33,
    'BE': 0.33, 'MA': 0.33, 'SI': 0.32, 'OM': 0.32, 'UR': 0.31,
}

# Spanish n-grams
ES_NGRAMS = {
    'DE': 1.82, 'LA': 1.54, 'EN': 1.48, 'EL': 1.45, 'QUE': 1.32,
    'ES': 1.28, 'OS': 1.15, 'ON': 1.10, 'AD': 1.05, 'AR': 1.02,
    'ER': 0.98, 'RE': 0.95, 'AL': 0.92, 'AN': 0.90, 'AS': 0.88,
    'RA': 0.85, 'ER': 0.83, 'LE': 0.82, 'RO': 0.80, 'CO': 0.78,
    'MA': 0.76, 'TA': 0.75, 'NA': 0.74, 'OR': 0.73, 'DO': 0.72,
    'TO': 0.71, 'SE': 0.70, 'CI': 0.69, 'IO': 0.68, 'NE': 0.67,
    'EC': 0.66, 'ON': 0.65, 'TE': 0.64, 'AC': 0.63, 'PA': 0.62,
    'LO': 0.61, 'MI': 0.60, 'NO': 0.59, 'SI': 0.58, 'UN': 0.57,
}

# Hebrew n-grams (transliterated)
HE_NGRAMS = {
    'HA': 1.62, 'VE': 1.48, 'MI': 1.35, 'LE': 1.32, 'BE': 1.28,
    'ET': 1.25, 'SHE': 1.22, 'LO': 1.18, 'KI': 1.15, 'AL': 1.12,
    'IM': 1.10, 'AN': 1.08, 'ME': 1.05, 'LA': 1.02, 'YE': 1.00,
    'TA': 0.98, 'RE': 0.95, 'MA': 0.93, 'NE': 0.90, 'HE': 0.88,
    'DE': 0.85, 'SE': 0.83, 'BA': 0.80, 'LI': 0.78, 'EH': 0.76,
    'RA': 0.74, 'SH': 0.72, 'CH': 0.70, 'AM': 0.68, 'EL': 0.66,
}

# Language scoring functions
LANGUAGE_TABLES = {
    'en': EN_NGRAMS,
    'es': ES_NGRAMS,
    'he': HE_NGRAMS,
}

def _ngram_score(text: str, n: int = 2) -> float:
    """Score text based on n-gram frequency (higher = more likely)."""
    if len(text) < n:
        return -float('inf')
    score = 0
    count = 0
    for lang, table in LANGUAGE_TABLES.items():
        for i in range(len(text) - n + 1):
            gram = text[i:i+n].upper()
            if gram in table:
                score += table[gram]
                count += 1
    return score / max(count, 1) if count > 0 else -float('inf')

def _language_score(text: str) -> tuple[str, float]:
    """Score text against all language tables and return best match."""
    if len(text) < 2:
        return 'en', 0.0
    best_score = -float('inf')
    best_lang = 'en'
    for lang, table in LANGUAGE_TABLES.items():
        score = 0
        count = 0
        for i in range(len(text) - 1):
            gram = text[i:i+2].upper()
            if gram in table:
                score += table[gram]
                count += 1
        score = score / max(count, 1) if count > 0 else -float('inf')
        if score > best_score:
            best_score = score
            best_lang = lang
    return best_lang, best_score

# ── Simple Substitution Cipher Solver ────────────────────────────────────────

def _generate_random_key() -> dict[str, str]:
    """Generate random substitution key."""
    alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    shuffled = alphabet.copy()
    random.shuffle(shuffled)
    return {a: s for a, s in zip(alphabet, shuffled)}

def _apply_key(text: str, key: dict[str, str]) -> str:
    """Apply substitution key to text."""
    result = []
    for c in text.upper():
        if c in key:
            result.append(key[c])
        else:
            result.append(c)
    return ''.join(result)

def _score_key(text: str, key: dict[str, str]) -> float:
    """Score a substitution key by n-gram frequency."""
    decrypted = _apply_key(text, key)
    return _ngram_score(decrypted)

def _mutate_key(key: dict[str, str]) -> dict[str, str]:
    """Mutate a substitution key by swapping two letters."""
    new_key = key.copy()
    a, b = random.sample(list(key.keys()), 2)
    new_key[a], new_key[b] = new_key[b], new_key[a]
    return new_key

def _hill_climb_substitution(text: str, max_iter: int = 1000) -> str | None:
    """Solve simple substitution cipher using hill-climbing."""
    # Clean text: keep only letters
    clean_text = ''.join(c.upper() for c in text if c.isalpha())
    if len(clean_text) < 10:
        return None

    # Start with random key
    current_key = _generate_random_key()
    current_score = _score_key(clean_text, current_key)

    # Hill-climbing
    for _ in range(max_iter):
        new_key = _mutate_key(current_key)
        new_score = _score_key(clean_text, new_key)
        if new_score > current_score:
            current_key = new_key
            current_score = new_score

    # Return best decryption
    return _apply_key(text, current_key)

def _genetic_substitution(text: str, pop_size: int = 100, max_gen: int = 50) -> str | None:
    """Solve simple substitution cipher using genetic algorithm."""
    clean_text = ''.join(c.upper() for c in text if c.isalpha())
    if len(clean_text) < 10:
        return None

    # Initialize population
    population = [_generate_random_key() for _ in range(pop_size)]
    scores = [_score_key(clean_text, k) for k in population]

    for _ in range(max_gen):
        # Selection: keep top 20%
        elite_size = max(5, pop_size // 5)
        elite = heapq.nlargest(elite_size, zip(scores, population), key=lambda x: x[0])
        elite_keys = [k for _, k in elite]
        elite_scores = [s for s, _ in elite]

        # Crossover: breed new generation
        new_population = elite_keys.copy()
        while len(new_population) < pop_size:
            parent1, parent2 = random.sample(elite_keys, 2)
            # Uniform crossover
            child = {}
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if random.random() < 0.5:
                    child[c] = parent1[c]
                else:
                    child[c] = parent2[c]
            # Repair: ensure all letters are present
            used = set(child.values())
            missing = [c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c not in used]
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if c not in child:
                    child[c] = missing.pop()
            new_population.append(child)

        # Mutation
        for i in range(elite_size, len(new_population)):
            if random.random() < 0.3:  # 30% mutation rate
                new_population[i] = _mutate_key(new_population[i])

        population = new_population
        scores = [_score_key(clean_text, k) for k in population]

    # Return best decryption
    best_idx = scores.index(max(scores))
    return _apply_key(text, population[best_idx])

def solve_substitution_cipher(text: str) -> str | None:
    """Try to solve simple substitution cipher using multiple methods."""
    try:
        # Try hill-climbing first (faster)
        result = _hill_climb_substitution(text, max_iter=500)
        if result and _ngram_score(result) > 0:
            return result
        # Fallback to genetic algorithm
        return _genetic_substitution(text, pop_size=50, max_gen=30)
    except Exception:
        return None

# ── Enhanced scoring with multi-language support ────────────────────────────

def score(original: str, result: str) -> tuple[int, list[str]]:
    """Return (score, notes_list) for a decoded result."""
    notes = []

    # Skip identical / empty
    if not result or result.strip() == original.strip():
        return -99, ["Output identical to input — skipped"]

    total = 0

    # +10 base: not empty and not identical
    total += 10
    notes.append("Output differs from input.")

    # +30 printable ASCII
    pr = printable_ratio(result)
    if pr > 0.85:
        total += 30
        notes.append(f"High printable ASCII ratio ({pr:.0%}).")

    # +25 CTF flag pattern
    if CTF_FLAG_RE.search(result):
        total += 25
        notes.append("Matched CTF flag pattern.")

    # +30 High-value domain patterns
    domain_patterns = [
        r'[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}',  # general domain
        r'google\.com', r'facebook\.com', r'amazon\.com', r'microsoft\.com',
        r'github\.com', r'youtube\.com', r'twitter\.com', r'linkedin\.com'
    ]
    for pattern in domain_patterns:
        if re.search(pattern, result.lower()):
            total += 30
            notes.append("Matched high-value domain pattern.")
            break  # Only add once

    # +20 language words (multi-language)
    words = re.findall(r'[a-zA-Z]{3,}', result.lower())
    if words:
        # Try all languages
        best_hits = 0
        best_lang = 'en'
        for lang in ['en', 'es', 'he']:
            lang_words = set()
            if lang == 'en':
                lang_words = ENGLISH_WORDS
            elif lang == 'es':
                # Spanish words (simplified)
                lang_words = {"el","la","de","que","y","a","en","un","ser","se","no","por",
                             "con","para","es","una","su","al","lo","como","más","pero","sus",
                             "le","ya","o","este","sí","porque","esta","entre","cuando","muy",
                             "sin","sobre","también","me","hasta","hay","donde","quien","desde",
                             "todo","nos","durante","todos","uno","les","ni","contra","otros","ese",
                             "eso","ante","ellos","e","esto","mí","antes","algunos","qué","unos",
                             "yo","otro","otras","otra","él","tanto","esa","estos","mucho","quienes",
                             "nada","muchos","cual","poco","ella","estar","estas","algunas","algo",
                             "nosotros","mi","mis","tú","te","ti","tu","tus","ellas","nosotras",
                             "vosotros","vosotras","os","mío","mía","míos","mías","tuyo","tuya",
                             "tuyos","tuyas","suyo","suya","suyos","suyas","nuestro","nuestra",
                             "nuestros","nuestras","vuestro","vuestra","vuestros","vuestras","esos",
                             "esas","estoy","estás","está","estamos","estáis","están","esté","estés",
                             "estemos","estéis","estén","estaré","estarás","estará","estaremos","estaréis",
                             "estarán","estaría","estarías","estaríamos","estaríais","estarían","estaba",
                             "estabas","estábamos","estabais","estaban","estuve","estuviste","estuvo",
                             "estuvimos","estuvisteis","estuvieron","estuviera","estuvieras","estuviéramos",
                             "estuvierais","estuvieran","estuviese","estuvieses","estuviésemos","estuvieseis",
                             "estuviesen","estando","estado","estada","estados","estadas","estad"}
            elif lang == 'he':
                # Hebrew words (transliterated)
                lang_words = {"ha","ve","mi","le","be","et","she","lo","ki","al",
                             "im","an","me","la","ye","ta","re","ma","ne","he",
                             "de","se","ba","li","eh","ra","sh","ch","am","el"}

            hits = sum(1 for w in words if w in lang_words)
            if hits > best_hits:
                best_hits = hits
                best_lang = lang

        if best_hits / len(words) > 0.2:
            total += 20
            notes.append(f"Contains common {best_lang} words ({best_hits}/{len(words)}).")

    # +15 lower entropy than input
    if entropy(result) < entropy(original):
        total += 15
        notes.append("Lower entropy than input.")

    # +10 n-gram score (multi-language)
    ngram_score = _ngram_score(result)
    if ngram_score > 0:
        total += 10
        notes.append(f"Good n-gram score ({ngram_score:.2f}).")

    # +10 substitution cipher score (if applicable)
    if len(result) > 20 and len(set(result.upper())) <= 26:
        sub_score = _ngram_score(result)
        if sub_score > 0.5:
            total += 10
            notes.append(f"Possible substitution cipher (score: {sub_score:.2f}).")

    return min(total, 100), notes
