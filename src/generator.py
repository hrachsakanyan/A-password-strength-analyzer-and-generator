"""
generator.py -- password and passphrase generation for PassGuard.

Everything here draws randomness from :mod:`secrets`, which is backed by the
operating system's cryptographic random source. The :mod:`random` module is
NOT used: it is a Mersenne Twister seeded from predictable state, and an
attacker who sees a handful of its outputs can reconstruct every other value
it will ever produce. ``random`` is for simulations, ``secrets`` is for keys.
"""

from __future__ import annotations

import math
import secrets
import string
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WORDLIST_FILE = DATA_DIR / "wordlist.txt"

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

#: Characters that are easy to misread when a password is written down.
AMBIGUOUS = "Il1O0oS5B8Z2|`'\""

#: PassGuard will happily generate a very short password if you insist -- the
#: analyzer is there to tell you how bad an idea that is.
MIN_LENGTH = 1
MAX_LENGTH = 256


class GeneratorError(ValueError):
    """Raised when the requested options cannot produce a password."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _shuffled(items: list[str]) -> list[str]:
    """Fisher-Yates shuffle driven by :func:`secrets.randbelow`."""
    items = list(items)
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]
    return items


def _strip_ambiguous(alphabet: str) -> str:
    return "".join(c for c in alphabet if c not in AMBIGUOUS)


def build_alphabet(
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> list[str]:
    """Return the selected character classes as a list of alphabets."""
    selected: list[str] = []
    for enabled, alphabet in (
        (use_lower, LOWERCASE),
        (use_upper, UPPERCASE),
        (use_digits, DIGITS),
        (use_symbols, SYMBOLS),
    ):
        if not enabled:
            continue
        if avoid_ambiguous:
            alphabet = _strip_ambiguous(alphabet)
        if alphabet:
            selected.append(alphabet)

    if not selected:
        raise GeneratorError("Select at least one character class.")
    return selected


def entropy_bits(length: int, alphabet_size: int) -> float:
    """Bits of entropy in *length* characters drawn from *alphabet_size*."""
    if length <= 0 or alphabet_size <= 1:
        return 0.0
    return round(length * math.log2(alphabet_size), 1)


# --------------------------------------------------------------------------- #
# Random passwords
# --------------------------------------------------------------------------- #


def generate_password(
    length: int = 16,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
    require_each_class: bool = True,
) -> str:
    """Generate one cryptographically random password.

    With *require_each_class* the result is guaranteed to contain at least one
    character from every selected class, which keeps it compatible with picky
    password policies. The guaranteed characters are placed first and the whole
    string is then shuffled, so their positions stay unpredictable.
    """
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise GeneratorError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    alphabets = build_alphabet(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous)
    if require_each_class and length < len(alphabets):
        raise GeneratorError(
            f"Length {length} is too short to include all {len(alphabets)} "
            "selected character classes."
        )

    combined = "".join(alphabets)
    chars: list[str] = []
    if require_each_class:
        chars.extend(secrets.choice(alphabet) for alphabet in alphabets)
    while len(chars) < length:
        chars.append(secrets.choice(combined))

    return "".join(_shuffled(chars))


def generate_many(count: int = 5, **options) -> list[str]:
    """Generate *count* independent passwords with the same options."""
    if count < 1:
        raise GeneratorError("Count must be at least 1.")
    return [generate_password(**options) for _ in range(count)]


def password_entropy(
    length: int,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> float:
    """Entropy of a password produced with these options, in bits."""
    alphabets = build_alphabet(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous)
    return entropy_bits(length, len("".join(alphabets)))


# --------------------------------------------------------------------------- #
# Passphrases
# --------------------------------------------------------------------------- #


def load_wordlist(path: Path | str = WORDLIST_FILE) -> list[str]:
    """Read the passphrase wordlist, skipping comments and duplicates."""
    path = Path(path)
    if not path.is_file():
        raise GeneratorError(f"Wordlist not found: {path}")

    words: list[str] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            word = line.strip().lower()
            if not word or word.startswith("#") or word in seen:
                continue
            seen.add(word)
            words.append(word)

    if len(words) < 16:
        raise GeneratorError(f"Wordlist {path} is too small to be useful.")
    return words


_WORDLIST_CACHE: dict[str, list[str]] = {}


def get_wordlist(path: Path | str = WORDLIST_FILE) -> list[str]:
    """Cached version of :func:`load_wordlist`."""
    key = str(path)
    if key not in _WORDLIST_CACHE:
        _WORDLIST_CACHE[key] = load_wordlist(path)
    return _WORDLIST_CACHE[key]


def generate_passphrase(
    words: int = 5,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
    add_symbol: bool = False,
    wordlist: list[str] | None = None,
) -> str:
    """Generate a random passphrase such as ``otter-canyon-brass-lilac-vault``.

    Words are chosen independently and with replacement, so the entropy is
    exactly ``words * log2(len(wordlist))`` -- see :func:`passphrase_entropy`.
    """
    if words < 2:
        raise GeneratorError("A passphrase needs at least 2 words.")

    pool = wordlist if wordlist is not None else get_wordlist()
    chosen = [secrets.choice(pool) for _ in range(words)]
    if capitalize:
        chosen = [word.capitalize() for word in chosen]

    phrase = separator.join(chosen)
    if add_number:
        phrase += separator + str(secrets.randbelow(100)).zfill(2)
    if add_symbol:
        phrase += secrets.choice(SYMBOLS)
    return phrase


def passphrase_entropy(
    words: int = 5,
    add_number: bool = False,
    add_symbol: bool = False,
    wordlist: list[str] | None = None,
) -> float:
    """Entropy of a passphrase with these options, in bits."""
    pool = wordlist if wordlist is not None else get_wordlist()
    bits = words * math.log2(len(pool))
    if add_number:
        bits += math.log2(100)
    if add_symbol:
        bits += math.log2(len(SYMBOLS))
    return round(bits, 1)


if __name__ == "__main__":  # a tiny self-demo: python src/generator.py
    print(generate_password(20))
    print(generate_passphrase(5))
