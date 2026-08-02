"""Tests for the generator. Run with: python -m unittest discover tests"""

from __future__ import annotations

import string
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from analyzer import analyze  # noqa: E402
from generator import (  # noqa: E402
    AMBIGUOUS,
    SYMBOLS,
    GeneratorError,
    build_alphabet,
    generate_many,
    generate_passphrase,
    generate_password,
    get_wordlist,
    passphrase_entropy,
    password_entropy,
)


class TestPasswordGeneration(unittest.TestCase):
    def test_default_length(self):
        self.assertEqual(len(generate_password()), 16)

    def test_requested_length_is_respected(self):
        for length in (4, 8, 12, 32, 128):
            with self.subTest(length=length):
                self.assertEqual(len(generate_password(length=length)), length)

    def test_every_selected_class_appears(self):
        for _ in range(50):
            password = generate_password(length=8)
            self.assertTrue(any(c in string.ascii_lowercase for c in password))
            self.assertTrue(any(c in string.ascii_uppercase for c in password))
            self.assertTrue(any(c in string.digits for c in password))
            self.assertTrue(any(c in SYMBOLS for c in password))

    def test_excluded_classes_stay_out(self):
        password = generate_password(length=40, use_symbols=False, use_digits=False)
        self.assertTrue(all(c in string.ascii_letters for c in password))

    def test_digits_only(self):
        pin = generate_password(
            length=6, use_lower=False, use_upper=False, use_symbols=False
        )
        self.assertTrue(pin.isdigit())

    def test_avoid_ambiguous(self):
        password = generate_password(length=60, avoid_ambiguous=True)
        self.assertFalse(any(c in AMBIGUOUS for c in password))

    def test_passwords_are_unique(self):
        passwords = generate_many(count=200, length=16)
        self.assertEqual(len(set(passwords)), 200)

    def test_guaranteed_characters_are_not_stuck_at_the_front(self):
        # With require_each_class the first four characters would always be
        # lower/upper/digit/symbol in that order if the shuffle were missing.
        firsts = {generate_password(length=12)[0] for _ in range(100)}
        self.assertGreater(len(firsts), 4)

    def test_rejects_impossible_options(self):
        with self.assertRaises(GeneratorError):
            generate_password(length=3)
        with self.assertRaises(GeneratorError):
            generate_password(length=300)
        with self.assertRaises(GeneratorError):
            generate_password(
                use_lower=False, use_upper=False, use_digits=False, use_symbols=False
            )
        with self.assertRaises(GeneratorError):
            generate_many(count=0)

    def test_too_short_for_all_classes(self):
        # Three characters cannot hold one of each of the four classes.
        with self.assertRaises(GeneratorError):
            generate_password(length=3, require_each_class=True)

    def test_short_password_allowed_without_the_class_guarantee(self):
        self.assertEqual(len(generate_password(length=3, require_each_class=False)), 3)

    def test_generated_passwords_analyse_as_strong(self):
        for _ in range(20):
            result = analyze(generate_password(length=16))
            self.assertGreaterEqual(result.score, 70, msg=f"weak output: {result.score}")

    def test_build_alphabet_returns_one_entry_per_class(self):
        self.assertEqual(len(build_alphabet()), 4)
        self.assertEqual(len(build_alphabet(use_symbols=False)), 3)

    def test_password_entropy_formula(self):
        # 16 characters from 26+26+10 = 62 symbols -> ~95.3 bits
        self.assertAlmostEqual(
            password_entropy(16, use_symbols=False), 95.3, places=1
        )


class TestPassphraseGeneration(unittest.TestCase):
    def test_word_count(self):
        phrase = generate_passphrase(words=5)
        self.assertEqual(len(phrase.split("-")), 5)

    def test_custom_separator(self):
        phrase = generate_passphrase(words=4, separator=".")
        self.assertEqual(len(phrase.split(".")), 4)

    def test_capitalize(self):
        phrase = generate_passphrase(words=4, capitalize=True)
        self.assertTrue(all(word[0].isupper() for word in phrase.split("-")))

    def test_extras_are_appended(self):
        phrase = generate_passphrase(words=3, add_number=True, add_symbol=True)
        self.assertIn(phrase[-1], SYMBOLS)
        self.assertTrue(any(c.isdigit() for c in phrase))

    def test_words_come_from_the_wordlist(self):
        words = set(get_wordlist())
        phrase = generate_passphrase(words=8)
        self.assertTrue(set(phrase.split("-")).issubset(words))

    def test_rejects_too_few_words(self):
        with self.assertRaises(GeneratorError):
            generate_passphrase(words=1)

    def test_passphrases_differ(self):
        phrases = {generate_passphrase(words=5) for _ in range(100)}
        self.assertGreater(len(phrases), 95)

    def test_entropy_grows_with_word_count(self):
        self.assertGreater(passphrase_entropy(words=6), passphrase_entropy(words=4))

    def test_wordlist_is_big_enough_to_matter(self):
        # Under 256 words a 5-word passphrase would fall below 40 bits.
        self.assertGreaterEqual(len(get_wordlist()), 256)


if __name__ == "__main__":
    unittest.main()
