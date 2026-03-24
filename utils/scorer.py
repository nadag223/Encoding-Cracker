"""Confidence scoring: rates how likely a decoded result is correct."""
import math
import re
import string

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
