"""
analyzer.py -- rule-based password strength analysis for PassGuard.

The analyzer is deliberately transparent: every point it awards or removes
comes from a rule you can read in this file, so the tool can explain *why* a
password is weak instead of only telling you that it is.

Two numbers are produced for every password:

  * entropy_bits -- how many guesses an attacker really needs, in bits.
    Patterns an attacker's cracking tool already knows (dictionary words,
    "abcd", "1111", "qwerty", leetspeak) are charged only a few bits instead
    of the full log2(alphabet) per character.

  * score (0-100) -- a friendlier summary built from length, character
    variety, entropy and a list of penalties.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field
from itertools import product
from pathlib import Path

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
COMMON_PASSWORDS_FILE = DATA_DIR / "common_passwords.txt"
DICTIONARY_FILE = DATA_DIR / "wordlist.txt"

#: Shortest / longest substring we try to match against the wordlists.
MIN_WORD_MATCH = 3
MAX_WORD_MATCH = 24

POOL_LOWER = 26
POOL_UPPER = 26
POOL_DIGITS = 10
POOL_SYMBOLS = len(string.punctuation)  # 32
POOL_OTHER = 100  # rough allowance for accented / non-ASCII characters

#: Character runs an attacker tries first, checked forwards and backwards.
SEQUENCES = (
    string.ascii_lowercase,
    string.digits,
)

#: A US keyboard, one string per physical row.
KEYBOARD_ROWS = (
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
)

#: Leetspeak substitutions. A tuple means the character is ambiguous and both
#: readings are tried ("1" can stand for either "i" or "l").
LEET_MAP: dict[str, tuple[str, ...]] = {
    "@": ("a",),
    "4": ("a",),
    "8": ("b",),
    "(": ("c",),
    "3": ("e",),
    "6": ("g",),
    "9": ("g",),
    "1": ("i", "l"),
    "!": ("i", "l"),
    "|": ("i", "l"),
    "0": ("o",),
    "5": ("s",),
    "$": ("s",),
    "7": ("t",),
    "+": ("t",),
    "2": ("z",),
}

#: How fast an attacker guesses, in guesses per second.
ATTACK_SCENARIOS = (
    ("Online, rate limited (100/hour)", 100 / 3600),
    ("Online, no rate limit (1k/sec)", 1_000),
    ("Offline, slow hash / bcrypt (10k/sec)", 10_000),
    ("Offline, fast hash / GPU (100B/sec)", 100_000_000_000),
)

#: Highest score a password may reach with too little real entropy:
#: (score ceiling, bits required to escape it). Checked from the top down.
ENTROPY_CEILINGS = (
    (19, 20),   # under 20 bits -> Very Weak, whatever else it does right
    (39, 28),   # under 28 bits -> Weak
    (59, 40),   # under 40 bits -> Fair
    (79, 60),   # under 60 bits -> Strong, but not Very Strong
)

#: Score bands: (minimum score, label).
VERDICTS = (
    (80, "Very Strong"),
    (60, "Strong"),
    (40, "Fair"),
    (20, "Weak"),
    (0, "Very Weak"),
)


# --------------------------------------------------------------------------- #
# Data holders
# --------------------------------------------------------------------------- #


@dataclass
class Match:
    """One recognisable chunk of a password found by the entropy estimator."""

    kind: str  # "common", "sequence", "keyboard", "repeat" or "random"
    token: str
    start: int
    bits: float
    note: str = ""

    @property
    def end(self) -> int:
        return self.start + len(self.token)


@dataclass
class Analysis:
    """Everything PassGuard knows about one password."""

    length: int
    score: int
    verdict: str
    entropy_bits: float
    theoretical_bits: float
    pool_size: int
    classes: dict[str, bool]
    matches: list[Match]
    feedback: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    is_common: bool = False
    common_rank: int | None = None

    @property
    def crack_times(self) -> dict[str, str]:
        """Human readable time-to-crack per attack scenario."""
        return {
            label: format_duration(guesses_needed(self.entropy_bits) / rate)
            for label, rate in ATTACK_SCENARIOS
        }

    def to_dict(self) -> dict:
        """A JSON-serialisable view (used by ``main.py --json``)."""
        return {
            "length": self.length,
            "score": self.score,
            "verdict": self.verdict,
            "entropy_bits": round(self.entropy_bits, 1),
            "theoretical_bits": round(self.theoretical_bits, 1),
            "pool_size": self.pool_size,
            "classes": self.classes,
            "is_common": self.is_common,
            "common_rank": self.common_rank,
            "patterns": [
                {"kind": m.kind, "token": m.token, "bits": round(m.bits, 1), "note": m.note}
                for m in self.matches
                if m.kind != "random"
            ],
            "feedback": self.feedback,
            "warnings": self.warnings,
            "crack_times": self.crack_times,
        }


# --------------------------------------------------------------------------- #
# Wordlist loading
# --------------------------------------------------------------------------- #


def load_common_passwords(path: Path | str = COMMON_PASSWORDS_FILE) -> dict[str, int]:
    """Read the offline wordlist into a ``{password: rank}`` mapping.

    Rank 1 is the most common password in the file. If the same password
    appears twice, the better (lower) rank wins. A missing file is not fatal:
    the analyzer simply loses the common-password rule.
    """
    ranked: dict[str, int] = {}
    path = Path(path)
    if not path.is_file():
        return ranked

    rank = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            rank += 1
            ranked.setdefault(word.lower(), rank)
    return ranked


_COMMON_CACHE: dict[str, dict[str, int]] = {}


def get_common_passwords(path: Path | str = COMMON_PASSWORDS_FILE) -> dict[str, int]:
    """Cached version of :func:`load_common_passwords`."""
    key = str(path)
    if key not in _COMMON_CACHE:
        _COMMON_CACHE[key] = load_common_passwords(path)
    return _COMMON_CACHE[key]


def load_dictionary(path: Path | str = DICTIONARY_FILE) -> set[str]:
    """Read the plain-word list used to recognise words inside a password.

    This is the same file the passphrase generator draws from, so PassGuard
    grades its own passphrases the way an attacker who owns the wordlist
    would -- roughly ``log2(len(wordlist))`` bits per word, not per character.
    """
    words: set[str] = set()
    path = Path(path)
    if not path.is_file():
        return words

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                words.add(word)
    return words


_DICTIONARY_CACHE: dict[str, set[str]] = {}


def get_dictionary(path: Path | str = DICTIONARY_FILE) -> set[str]:
    """Cached version of :func:`load_dictionary`."""
    key = str(path)
    if key not in _DICTIONARY_CACHE:
        _DICTIONARY_CACHE[key] = load_dictionary(path)
    return _DICTIONARY_CACHE[key]


# --------------------------------------------------------------------------- #
# Character classes and the theoretical alphabet
# --------------------------------------------------------------------------- #


def classify(password: str) -> dict[str, bool]:
    """Which character classes appear in *password*."""
    return {
        "lowercase": any(c in string.ascii_lowercase for c in password),
        "uppercase": any(c in string.ascii_uppercase for c in password),
        "digits": any(c in string.digits for c in password),
        "symbols": any(c in string.punctuation for c in password),
        "other": any(
            c not in string.ascii_letters + string.digits + string.punctuation
            for c in password
        ),
    }


def pool_size(password: str) -> int:
    """Size of the alphabet an attacker would have to brute force."""
    classes = classify(password)
    size = 0
    if classes["lowercase"]:
        size += POOL_LOWER
    if classes["uppercase"]:
        size += POOL_UPPER
    if classes["digits"]:
        size += POOL_DIGITS
    if classes["symbols"]:
        size += POOL_SYMBOLS
    if classes["other"]:
        size += POOL_OTHER
    return size


def theoretical_entropy(password: str) -> float:
    """``length * log2(alphabet)`` -- the naive upper bound on strength."""
    size = pool_size(password)
    if size <= 1 or not password:
        return 0.0
    return len(password) * math.log2(size)


# --------------------------------------------------------------------------- #
# Pattern detection
# --------------------------------------------------------------------------- #


def leet_variants(token: str, max_variants: int = 32) -> list[str]:
    """Undo leetspeak, returning every plausible reading of *token*.

    ``"p@55w0rd"`` -> ``["passwords"...]`` style expansions. Ambiguous
    characters branch, so the number of variants is capped to stay cheap.
    """
    token = token.lower()
    if not any(c in LEET_MAP for c in token):
        return [token]

    options: list[tuple[str, ...]] = []
    branches = 1
    for char in token:
        choices = LEET_MAP.get(char)
        if not choices:
            options.append((char,))
        elif len(choices) == 1 or branches * len(choices) > max_variants:
            # Unambiguous, or we already have enough variants: take the first
            # reading and also keep the original character as a fallback.
            options.append((choices[0],))
        else:
            branches *= len(choices)
            options.append(choices)

    variants = ["".join(combo) for combo in product(*options)]
    if token not in variants:
        variants.append(token)
    return variants


def _capitalisation_bits(token: str) -> float:
    """Extra guesses an attacker spends on the capitalisation of a word."""
    letters = [c for c in token if c.isalpha()]
    if not letters:
        return 0.0
    if all(c.islower() for c in letters):
        return 0.0  # all lowercase is the default guess
    if all(c.isupper() for c in letters):
        return 1.0
    if letters[0].isupper() and all(c.islower() for c in letters[1:]):
        return 1.0  # Capitalised
    return min(len(letters), 8)  # unusual mixed case is genuinely harder


def find_common_match(token: str, common: dict[str, int]) -> tuple[int, str] | None:
    """Look *token* up in the common-password list, tolerating case and leetspeak.

    Returns ``(rank, note)`` or ``None``.
    """
    lowered = token.lower()
    if lowered in common:
        return common[lowered], "common password"

    for variant in leet_variants(lowered):
        if variant in common:
            return common[variant], "common password with leetspeak"
    return None


def find_word_match(
    token: str, common: dict[str, int], dictionary: set[str]
) -> tuple[float, str] | None:
    """Cost of guessing *token* from a wordlist, in bits, or ``None``.

    Known passwords are charged by their rank (the most common password costs
    one guess); plain dictionary words are charged ``log2(dictionary size)``
    because the attacker has no reason to prefer one word over another.
    """
    found = find_common_match(token, common)
    if found:
        rank, note = found
        bits = math.log2(rank + 1)
        if "leetspeak" in note:
            bits += 1.0  # the attacker also guesses the substitution style
        return bits, note

    if not dictionary:
        return None

    lowered = token.lower()
    word_bits = math.log2(len(dictionary))
    if lowered in dictionary:
        return word_bits, "dictionary word"

    for variant in leet_variants(lowered):
        if variant in dictionary:
            return word_bits + 1.0, "dictionary word with leetspeak"
    return None


def _sequence_run(password: str, start: int) -> int:
    """Length of an alphabet/digit run (``abcd``, ``5432``) starting at *start*."""
    best = 0
    for alphabet in SEQUENCES:
        for text in (alphabet, alphabet[::-1]):
            length = 0
            while start + length < len(password):
                char = password[start + length].lower()
                index = text.find(char)
                if index == -1:
                    break
                if length == 0:
                    first_index = index
                elif index != first_index + length:
                    break
                length += 1
            if length >= 3:
                best = max(best, length)
    return best


def _keyboard_run(password: str, start: int) -> int:
    """Length of a keyboard walk (``qwerty``, ``asdf``) starting at *start*."""
    best = 0
    for row in KEYBOARD_ROWS:
        for text in (row, row[::-1]):
            length = 0
            first_index = -1
            while start + length < len(password):
                index = text.find(password[start + length].lower())
                if index == -1:
                    break
                if length == 0:
                    first_index = index
                elif index != first_index + length:
                    break
                length += 1
            if length >= 4:
                best = max(best, length)
    return best


def _repeat_match(password: str, start: int, per_char_bits: float) -> Match | None:
    """Longest repetition starting at *start*: ``aaa``, ``111``, ``Aa1!Aa1!``.

    A repetition costs the attacker one guess for the repeated block plus
    ``log2(number of repeats)``, no matter how long the whole run is.
    """
    remaining = len(password) - start
    best: Match | None = None
    best_saving = 0.0

    for base_len in range(1, remaining // 2 + 1):
        base = password[start : start + base_len]
        count = 1
        while password[start + count * base_len : start + (count + 1) * base_len] == base:
            count += 1

        total = base_len * count
        if count < 2 or total < 3:
            continue

        bits = base_len * per_char_bits + math.log2(count)
        saving = total * per_char_bits - bits
        if saving > best_saving:
            note = "repeated character" if base_len == 1 else "repeated block"
            best = Match("repeat", password[start : start + total], start, bits, note)
            best_saving = saving

    return best


# --------------------------------------------------------------------------- #
# Entropy estimation
# --------------------------------------------------------------------------- #


def estimate_entropy(
    password: str,
    common: dict[str, int] | None = None,
    dictionary: set[str] | None = None,
) -> tuple[float, list[Match]]:
    """Estimate how many bits of guessing *password* really costs.

    The password is scanned left to right. At each position the estimator
    collects candidate patterns (dictionary word, character sequence, keyboard
    walk, repeated character) and keeps the one that saves the attacker the
    most work compared with brute forcing those characters. Anything that is
    not part of a pattern costs the full ``log2(alphabet)`` bits.
    """
    if not password:
        return 0.0, []

    if common is None:
        common = get_common_passwords()
    if dictionary is None:
        dictionary = get_dictionary()

    size = pool_size(password)
    per_char_bits = math.log2(size) if size > 1 else 1.0

    matches: list[Match] = []
    index = 0
    while index < len(password):
        candidates: list[Match] = []

        # 1. Known password or dictionary word, longest first.
        longest = min(MAX_WORD_MATCH, len(password) - index)
        for length in range(longest, MIN_WORD_MATCH - 1, -1):
            token = password[index : index + length]
            found = find_word_match(token, common, dictionary)
            if found:
                bits, note = found
                bits += _capitalisation_bits(token)
                kind = "common" if note.startswith("common") else "word"
                candidates.append(Match(kind, token, index, bits, note))
                break

        # 2. Sequences such as "abcdef" or "9876".
        length = _sequence_run(password, index)
        if length:
            token = password[index : index + length]
            # ~6 bits to pick the alphabet, direction and starting character,
            # plus log2(length) for how far the run goes.
            bits = 6.0 + math.log2(length) + _capitalisation_bits(token)
            candidates.append(Match("sequence", token, index, bits, "character sequence"))

        # 3. Keyboard walks such as "qwerty" or "asdfgh".
        length = _keyboard_run(password, index)
        if length:
            token = password[index : index + length]
            bits = 7.0 + math.log2(length) + _capitalisation_bits(token)
            candidates.append(Match("keyboard", token, index, bits, "keyboard pattern"))

        # 4. Repetition, of one character ("aaaa") or of a block ("Aa1!Aa1!").
        repeat = _repeat_match(password, index, per_char_bits)
        if repeat:
            candidates.append(repeat)

        # Keep the candidate that saves the attacker the most work. A pattern
        # is only worth recording if it is cheaper than brute force.
        best = None
        best_saving = 0.0
        for candidate in candidates:
            saving = len(candidate.token) * per_char_bits - candidate.bits
            if saving > best_saving:
                best, best_saving = candidate, saving

        if best is None:
            matches.append(Match("random", password[index], index, per_char_bits))
            index += 1
        else:
            matches.append(best)
            index = best.end

    bits = sum(m.bits for m in matches)

    # An attacker also has to guess how the chunks are arranged. Adding
    # log2(chunks!) keeps multi-word passphrases from being undersold.
    chunk_count = sum(1 for m in matches if m.kind != "random")
    if chunk_count > 1:
        bits += math.log2(math.factorial(chunk_count))

    return round(bits, 2), matches


# --------------------------------------------------------------------------- #
# Crack-time helpers
# --------------------------------------------------------------------------- #


def guesses_needed(bits: float) -> float:
    """Average number of guesses to break a password worth *bits* bits."""
    bits = max(0.0, min(bits, 1000.0))  # keep the float from overflowing
    return 2.0 ** max(0.0, bits - 1)


def format_duration(seconds: float) -> str:
    """Turn a number of seconds into something a human can read."""
    if seconds < 1:
        return "instantly"

    units = (
        ("second", "seconds", 60),
        ("minute", "minutes", 60),
        ("hour", "hours", 24),
        ("day", "days", 30),
        ("month", "months", 12),
        ("year", "years", 100),
        ("century", "centuries", 1000),
    )
    value = seconds
    for singular, plural, step in units:
        if value < step:
            amount = int(round(value))
            return f"{amount:,} {singular if amount == 1 else plural}"
        value /= step

    if value > 1e12:
        return "longer than the age of the universe"
    return f"{value:,.0f} millennia"


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


def verdict_for(score: int) -> str:
    """Map a 0-100 score onto a label."""
    for minimum, label in VERDICTS:
        if score >= minimum:
            return label
    return VERDICTS[-1][1]


def analyze(
    password: str,
    common: dict[str, int] | None = None,
    dictionary: set[str] | None = None,
) -> Analysis:
    """Score *password* from 0 to 100 and explain the result.

    Scoring rules (see the table in README.md):

      length     0-40 pts   3.5 points per character beyond the 4th
      variety    0-30 pts   lowercase 5, uppercase 8, digits 7, symbols 10
      entropy    0-30 pts   0.5 points per bit of *estimated* entropy

      penalties  -15  shorter than 8 characters
                 -10  only one character class
                 -15  a dictionary word covers half the password or more
                 -8   per distinct weak pattern (sequence / keyboard / repeat)
                 cap  a password found verbatim in the wordlist scores <= 10
    """
    if common is None:
        common = get_common_passwords()
    if dictionary is None:
        dictionary = get_dictionary()

    classes = classify(password)
    length = len(password)
    entropy_bits, matches = estimate_entropy(password, common, dictionary)

    feedback: list[str] = []
    warnings: list[str] = []

    if not password:
        return Analysis(
            length=0,
            score=0,
            verdict=verdict_for(0),
            entropy_bits=0.0,
            theoretical_bits=0.0,
            pool_size=0,
            classes=classes,
            matches=[],
            feedback=["Enter a password to analyse."],
            warnings=["Empty password."],
        )

    # --- positive points -------------------------------------------------- #
    length_points = max(0.0, min(40.0, (length - 4) * 3.5))

    variety_points = 0.0
    if classes["lowercase"]:
        variety_points += 5
    if classes["uppercase"]:
        variety_points += 8
    if classes["digits"]:
        variety_points += 7
    if classes["symbols"]:
        variety_points += 10
    if classes["other"]:
        variety_points += 5
    variety_points = min(30.0, variety_points)

    entropy_points = min(30.0, entropy_bits * 0.5)

    score = length_points + variety_points + entropy_points

    # --- penalties -------------------------------------------------------- #
    if length < 8:
        score -= 15
        warnings.append(f"Only {length} characters long -- far too short.")

    class_count = sum(1 for key, present in classes.items() if present and key != "other")
    if class_count <= 1:
        score -= 10
        warnings.append("Uses a single type of character.")

    seen_kinds: set[str] = set()
    for match in matches:
        if match.kind in ("sequence", "keyboard", "repeat") and match.kind not in seen_kinds:
            seen_kinds.add(match.kind)
            score -= 8
            warnings.append(f"Contains a {match.note}: '{match.token}'.")

    common_chars = sum(len(m.token) for m in matches if m.kind == "common")
    if common_chars and common_chars >= length / 2:
        score -= 15
        words = ", ".join(f"'{m.token}'" for m in matches if m.kind == "common")
        warnings.append(f"Built mostly from known password(s): {words}.")

    # A single dictionary word dressed up with digits is weak; four or five of
    # them is a passphrase, which is fine -- the entropy term already prices it.
    word_matches = [m for m in matches if m.kind == "word"]
    word_chars = sum(len(m.token) for m in word_matches)
    single_word_password = (
        len(word_matches) <= 2 and word_chars >= length / 2 and not common_chars
    )
    if single_word_password:
        score -= 10
        words = ", ".join(f"'{m.token}'" for m in word_matches)
        warnings.append(f"Built around a dictionary word: {words}.")

    # --- entropy ceiling --------------------------------------------------- #
    # Length and variety points must never outvote guessability: a long,
    # mixed-case, symbol-rich password built from a known pattern is still
    # only worth the guesses it costs.
    for ceiling, bits_required in ENTROPY_CEILINGS:
        if entropy_bits < bits_required:
            if score > ceiling:
                score = ceiling
                warnings.append(
                    f"Looks complex, but only {entropy_bits:.0f} bits of real "
                    "entropy -- the pattern is predictable."
                )
            break

    # --- the hard stop: the whole password is in the wordlist -------------- #
    exact = find_common_match(password, common)
    is_common = exact is not None
    common_rank = exact[0] if exact else None
    if is_common:
        score = min(score, 10)
        warnings.insert(
            0,
            f"This password is #{common_rank} in the common-password list -- "
            "attackers try it in the first seconds.",
        )

    score = int(max(0, min(100, round(score))))

    # --- constructive advice ---------------------------------------------- #
    if length < 12:
        feedback.append("Make it at least 12 characters -- length beats complexity.")
    elif length < 16 and score < 80:
        feedback.append("Growing to 16+ characters is the cheapest way to get stronger.")

    if not classes["lowercase"]:
        feedback.append("Add lowercase letters.")
    if not classes["uppercase"]:
        feedback.append("Add uppercase letters.")
    if not classes["digits"]:
        feedback.append("Add digits.")
    if not classes["symbols"]:
        feedback.append("Add symbols such as ! ? # % &.")

    if is_common:
        feedback.append("Choose something that is not on any published password list.")
    elif common_chars:
        feedback.append("Avoid known passwords -- cracking tools start with them.")
    elif single_word_password:
        feedback.append(
            "One word plus a few digits is a pattern attackers expect. "
            "Use several unrelated words, or random characters."
        )

    if "sequence" in seen_kinds or "keyboard" in seen_kinds:
        feedback.append("Drop keyboard walks and counting patterns like 'abcd' or 'qwerty'.")
    if "repeat" in seen_kinds:
        feedback.append("Avoid repeating the same character several times.")

    if score >= 80 and not feedback:
        feedback.append("Strong password -- store it in a password manager, do not reuse it.")
    elif score >= 60 and not feedback:
        feedback.append("Good password. A few more characters would make it excellent.")

    return Analysis(
        length=length,
        score=score,
        verdict=verdict_for(score),
        entropy_bits=entropy_bits,
        theoretical_bits=round(theoretical_entropy(password), 2),
        pool_size=pool_size(password),
        classes=classes,
        matches=matches,
        feedback=feedback,
        warnings=warnings,
        is_common=is_common,
        common_rank=common_rank,
    )


if __name__ == "__main__":  # a tiny self-demo: python src/analyzer.py
    for sample in ("123456", "Tr0ub4dor&3", "correct-horse-battery-staple", "qP7!vZm2$Ld9Rx"):
        result = analyze(sample)
        print(f"{sample!r:35} {result.score:3d}/100  {result.verdict:12} "
              f"{result.entropy_bits:6.1f} bits")
