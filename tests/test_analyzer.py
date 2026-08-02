"""Tests for the strength analyzer. Run with: python -m unittest discover tests"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from analyzer import (  # noqa: E402
    analyze,
    classify,
    estimate_entropy,
    format_duration,
    get_common_passwords,
    leet_variants,
    pool_size,
    theoretical_entropy,
    verdict_for,
)


class TestCharacterClasses(unittest.TestCase):
    def test_classify_detects_every_class(self):
        classes = classify("aA1!")
        self.assertTrue(classes["lowercase"])
        self.assertTrue(classes["uppercase"])
        self.assertTrue(classes["digits"])
        self.assertTrue(classes["symbols"])
        self.assertFalse(classes["other"])

    def test_classify_on_single_class(self):
        classes = classify("abcdef")
        self.assertTrue(classes["lowercase"])
        self.assertFalse(classes["uppercase"])
        self.assertFalse(classes["digits"])
        self.assertFalse(classes["symbols"])

    def test_pool_size_adds_up(self):
        self.assertEqual(pool_size("abc"), 26)
        self.assertEqual(pool_size("abc123"), 36)
        self.assertEqual(pool_size("abcABC123"), 62)

    def test_pool_size_of_empty_password(self):
        self.assertEqual(pool_size(""), 0)

    def test_theoretical_entropy_matches_formula(self):
        # 10 lowercase characters = 10 * log2(26) = 47.0 bits
        self.assertAlmostEqual(theoretical_entropy("abcdefghij"), 47.0, places=1)


class TestLeetspeak(unittest.TestCase):
    def test_unambiguous_substitution(self):
        self.assertIn("password", leet_variants("p@55w0rd"))

    def test_ambiguous_character_branches(self):
        variants = leet_variants("h1")
        self.assertIn("hi", variants)
        self.assertIn("hl", variants)

    def test_plain_word_is_returned_unchanged(self):
        self.assertEqual(leet_variants("horse"), ["horse"])

    def test_variant_count_stays_bounded(self):
        self.assertLessEqual(len(leet_variants("1" * 20)), 33)


class TestEntropyEstimate(unittest.TestCase):
    def test_random_password_is_close_to_theoretical(self):
        bits, _ = estimate_entropy("qP7!vZm2$Ld9Rx")
        self.assertGreater(bits, 70)

    def test_patterns_cost_far_less_than_brute_force(self):
        bits, _ = estimate_entropy("abcdefghijklmnop")
        self.assertLess(bits, theoretical_entropy("abcdefghijklmnop") / 3)

    def test_repeated_characters_are_cheap(self):
        bits, matches = estimate_entropy("aaaaaaaaaaaa")
        self.assertLess(bits, 15)
        self.assertEqual(matches[0].kind, "repeat")

    def test_keyboard_walk_is_detected(self):
        # 'fghjkl' is a keyboard row walk that is not itself in the wordlist.
        _, matches = estimate_entropy("Kq7fghjkl")
        self.assertTrue(any(m.kind == "keyboard" for m in matches))

    def test_listed_password_beats_the_keyboard_rule(self):
        # 'qwertyuiop' is a well known password, so guessing it from a list is
        # cheaper for the attacker than walking the keyboard.
        _, matches = estimate_entropy("qwertyuiop")
        self.assertEqual([m.kind for m in matches], ["common"])

    def test_common_word_is_detected(self):
        _, matches = estimate_entropy("password")
        self.assertTrue(any(m.kind == "common" for m in matches))

    def test_repeated_block_is_detected(self):
        bits, matches = estimate_entropy("Aa1!Aa1!Aa1!")
        self.assertEqual(matches[0].kind, "repeat")
        self.assertEqual(matches[0].note, "repeated block")
        # Three copies of a 4-character block cost about one block plus log2(3).
        self.assertLess(bits, 35)

    def test_dictionary_words_are_priced_per_word(self):
        _, matches = estimate_entropy("otter-canyon-brass-anchor-vault")
        words = [m for m in matches if m.kind == "word"]
        self.assertGreaterEqual(len(words), 4)
        # log2(1084 words) is about 10 bits, so no word should cost much more.
        self.assertTrue(all(m.bits < 14 for m in words))

    def test_passphrase_is_not_treated_as_random_characters(self):
        phrase = "otter-canyon-brass-anchor-vault"
        bits, _ = estimate_entropy(phrase)
        self.assertLess(bits, theoretical_entropy(phrase) / 2)

    def test_empty_password_has_no_entropy(self):
        bits, matches = estimate_entropy("")
        self.assertEqual(bits, 0.0)
        self.assertEqual(matches, [])

    def test_longer_random_password_has_more_entropy(self):
        short, _ = estimate_entropy("xK9#mQ2v")
        long, _ = estimate_entropy("xK9#mQ2vRt7$Bn4W")
        self.assertGreater(long, short)


class TestScoring(unittest.TestCase):
    def test_common_password_is_capped(self):
        result = analyze("123456")
        self.assertLessEqual(result.score, 10)
        self.assertTrue(result.is_common)
        self.assertEqual(result.common_rank, 1)

    def test_common_password_with_leetspeak_is_still_caught(self):
        self.assertTrue(analyze("p@ssw0rd").is_common)

    def test_random_password_scores_well(self):
        result = analyze("qP7!vZm2$Ld9Rx#4")
        self.assertGreaterEqual(result.score, 80)
        self.assertEqual(result.verdict, "Very Strong")

    def test_passphrase_scores_well(self):
        result = analyze("otter-canyon-brass-anchor-vault")
        self.assertGreaterEqual(result.score, 60)

    def test_short_password_is_weak(self):
        result = analyze("Ab1!")
        self.assertLess(result.score, 40)
        self.assertTrue(any("short" in w for w in result.warnings))

    def test_single_class_is_penalised(self):
        result = analyze("kdjfhskdjfhs")
        self.assertTrue(any("single type" in w for w in result.warnings))

    def test_empty_password(self):
        result = analyze("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.verdict, "Very Weak")
        self.assertEqual(result.length, 0)

    def test_score_is_always_in_range(self):
        samples = ["", "a", "123456", "correct horse battery staple",
                   "!" * 200, "Tr0ub4dor&3", "հայերեն"]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(0 <= analyze(sample).score <= 100)

    def test_complexity_theatre_is_capped_by_entropy(self):
        # Every character class, 11 characters long -- and still a known
        # password with a counting pattern glued on.
        result = analyze("P@ssw0rd123")
        self.assertLess(result.score, 40)
        self.assertTrue(all(result.classes[c] for c in
                            ("lowercase", "uppercase", "digits", "symbols")))

    def test_repeated_block_beats_the_variety_bonus(self):
        result = analyze("Aa1!Aa1!Aa1!")
        self.assertLessEqual(result.score, 39)
        self.assertTrue(any("repeated block" in w for w in result.warnings))

    def test_single_word_plus_digits_is_penalised(self):
        result = analyze("parsley2024")
        self.assertTrue(any("dictionary word" in w for w in result.warnings))

    def test_passphrase_is_not_scolded_for_using_words(self):
        result = analyze("otter-canyon-brass-anchor-vault")
        self.assertFalse(any("dictionary word" in w for w in result.warnings))

    def test_feedback_is_actionable(self):
        result = analyze("alllowercaseletters")
        self.assertTrue(result.feedback)
        self.assertTrue(any("uppercase" in tip.lower() for tip in result.feedback))

    def test_stronger_password_scores_higher(self):
        weak = analyze("password1").score
        strong = analyze("7#tRv!Qz2Lm9Xa$B").score
        self.assertGreater(strong, weak)

    def test_json_view_is_serialisable(self):
        import json

        payload = json.dumps(analyze("Tr0ub4dor&3").to_dict())
        self.assertIn("entropy_bits", payload)


class TestHelpers(unittest.TestCase):
    def test_verdict_bands(self):
        self.assertEqual(verdict_for(0), "Very Weak")
        self.assertEqual(verdict_for(30), "Weak")
        self.assertEqual(verdict_for(50), "Fair")
        self.assertEqual(verdict_for(70), "Strong")
        self.assertEqual(verdict_for(100), "Very Strong")

    def test_format_duration(self):
        self.assertEqual(format_duration(0.4), "instantly")
        self.assertIn("second", format_duration(30))
        self.assertIn("hour", format_duration(3600 * 5))
        self.assertIn("year", format_duration(3600 * 24 * 365 * 5))

    def test_wordlist_loads_and_is_ranked(self):
        common = get_common_passwords()
        self.assertGreater(len(common), 100)
        self.assertEqual(common["123456"], 1)
        self.assertNotIn("#", "".join(list(common)[:5]))


if __name__ == "__main__":
    unittest.main()
