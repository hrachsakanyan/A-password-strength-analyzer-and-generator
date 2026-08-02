"""
main.py -- the PassGuard command line interface.

    python src/main.py                      interactive menu
    python src/main.py check "hunter2"      analyse a password
    python src/main.py check --hidden       analyse without echoing it
    python src/main.py gen -l 20 -n 5       generate 5 passwords, 20 chars
    python src/main.py passphrase -w 6      generate a 6-word passphrase

Nothing typed into PassGuard is ever written to disk or sent anywhere; the
program only reads its own offline wordlists.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from getpass import getpass
from pathlib import Path

# Allow both "python src/main.py" and "python -m src.main" to find the modules.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import Analysis, analyze, get_common_passwords  # noqa: E402
from generator import (  # noqa: E402
    GeneratorError,
    generate_passphrase,
    generate_password,
    get_wordlist,
    passphrase_entropy,
    password_entropy,
)

# --------------------------------------------------------------------------- #
# Terminal output helpers
# --------------------------------------------------------------------------- #

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "Very Weak": "\033[91m",
    "Weak": "\033[91m",
    "Fair": "\033[93m",
    "Strong": "\033[92m",
    "Very Strong": "\033[92m",
}


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # Ask Windows to interpret ANSI escape codes in this console.
        os.system("")
    return True


USE_COLOR = _colors_enabled()


def paint(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if USE_COLOR else text


def strength_bar(score: int, width: int = 30) -> str:
    """A ``[#####-----]`` style meter for the score."""
    filled = int(round(score / 100 * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def print_analysis(result: Analysis, verbose: bool = False) -> None:
    """Render an :class:`Analysis` as a readable report."""
    color = COLORS.get(result.verdict, "")
    print()
    print(paint(f"  {result.verdict.upper()}  {result.score}/100", BOLD + color))
    print(f"  {paint(strength_bar(result.score), color)}")
    print()
    print(f"  Length          : {result.length} characters")
    present = [name for name, ok in result.classes.items() if ok]
    print(f"  Character types : {', '.join(present) if present else 'none'}")
    print(f"  Entropy         : {result.entropy_bits:.1f} bits "
          f"(brute-force upper bound {result.theoretical_bits:.1f})")
    print(f"  Cracking time   : {result.crack_times['Offline, fast hash / GPU (100B/sec)']} "
          f"{paint('(offline GPU attack)', DIM)}")

    if result.warnings:
        print()
        print(paint("  Problems found:", BOLD))
        for warning in result.warnings:
            print(f"    {paint('x', COLORS['Weak'])} {warning}")

    if result.feedback:
        print()
        print(paint("  How to improve:", BOLD))
        for tip in result.feedback:
            print(f"    - {tip}")

    if verbose:
        patterns = [m for m in result.matches if m.kind != "random"]
        if patterns:
            print()
            print(paint("  Patterns an attacker would recognise:", BOLD))
            for match in patterns:
                print(f"    {match.token!r:24} {match.note:32} {match.bits:5.1f} bits")
        print()
        print(paint("  Estimated time to crack:", BOLD))
        for label, value in result.crack_times.items():
            print(f"    {label:40} {value}")
    print()


def copy_to_clipboard(text: str) -> bool:
    """Copy *text* to the system clipboard using only OS tools. Best effort."""
    if sys.platform == "win32":
        commands = [["clip"]]
    elif sys.platform == "darwin":
        commands = [["pbcopy"]]
    else:
        commands = [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]

    for command in commands:
        if shutil.which(command[0]) is None:
            continue
        try:
            subprocess.run(command, input=text.encode("utf-8"), check=True)
            return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def command_check(args: argparse.Namespace) -> int:
    if args.hidden or args.password is None:
        password = getpass("Password (not shown): ")
    else:
        password = args.password

    result = analyze(password)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_analysis(result, verbose=args.verbose)

    # Exit code 1 when the password is below the "Strong" band, so the tool
    # can be used inside scripts and CI checks.
    return 0 if result.score >= args.min_score else 1


def command_gen(args: argparse.Namespace) -> int:
    options = dict(
        length=args.length,
        use_lower=not args.no_lower,
        use_upper=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
        avoid_ambiguous=args.no_ambiguous,
    )

    passwords = [generate_password(**options) for _ in range(args.count)]
    bits = password_entropy(**options)

    for password in passwords:
        print(password)

    if not args.quiet:
        print(paint(f"\n  {bits:.0f} bits of entropy per password "
                    f"({args.length} chars, generated with secrets)", DIM))
    if args.copy:
        ok = copy_to_clipboard(passwords[-1])
        print(paint("  Copied to clipboard." if ok else
                    "  Could not reach a clipboard tool.", DIM))
    if args.check:
        print_analysis(analyze(passwords[-1]), verbose=args.verbose)
    return 0


def command_passphrase(args: argparse.Namespace) -> int:
    wordlist = get_wordlist()
    phrases = [
        generate_passphrase(
            words=args.words,
            separator=args.separator,
            capitalize=args.capitalize,
            add_number=args.number,
            add_symbol=args.symbol,
            wordlist=wordlist,
        )
        for _ in range(args.count)
    ]
    bits = passphrase_entropy(
        words=args.words, add_number=args.number, add_symbol=args.symbol, wordlist=wordlist
    )

    for phrase in phrases:
        print(phrase)

    if not args.quiet:
        print(paint(f"\n  {bits:.0f} bits of entropy per passphrase "
                    f"({args.words} words from {len(wordlist)} choices)", DIM))
    if args.copy:
        ok = copy_to_clipboard(phrases[-1])
        print(paint("  Copied to clipboard." if ok else
                    "  Could not reach a clipboard tool.", DIM))
    if args.check:
        print_analysis(analyze(phrases[-1]), verbose=args.verbose)
    return 0


# --------------------------------------------------------------------------- #
# Interactive menu (shown when PassGuard is started with no arguments)
# --------------------------------------------------------------------------- #

BANNER = r"""
  ____               ____                     _
 |  _ \ __ _ ___ ___ / ___|_   _  __ _ _ __ __| |
 | |_) / _` / __/ __| |  _| | | |/ _` | '__/ _` |
 |  __/ (_| \__ \__ \ |_| | |_| | (_| | | | (_| |
 |_|   \__,_|___/___/\____|\__,_|\__,_|_|  \__,_|
   password strength analyzer & generator
"""


def _ask_int(prompt: str, default: int, low: int, high: int) -> int:
    raw = input(f"{prompt} [{default}]: ").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(f"  Not a number, using {default}.")
        return default
    if not low <= value <= high:
        print(f"  Out of range ({low}-{high}), using {default}.")
        return default
    return value


def _ask_yes(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw.startswith("y")


def interactive() -> int:
    print(paint(BANNER, BOLD))
    common = get_common_passwords()
    print(f"  Loaded {len(common):,} common passwords "
          f"and {len(get_wordlist()):,} passphrase words.\n")

    while True:
        print("  1) Check a password")
        print("  2) Generate a password")
        print("  3) Generate a passphrase")
        print("  4) Quit")
        choice = input("\n  Choose: ").strip()

        if choice == "1":
            hidden = _ask_yes("  Hide what you type?", default=False)
            password = getpass("  Password: ") if hidden else input("  Password: ")
            print_analysis(analyze(password, common), verbose=True)
        elif choice == "2":
            length = _ask_int("  Length", 16, 4, 256)
            symbols = _ask_yes("  Include symbols?", True)
            digits = _ask_yes("  Include digits?", True)
            try:
                password = generate_password(
                    length=length, use_symbols=symbols, use_digits=digits
                )
            except GeneratorError as error:
                print(f"  {error}\n")
                continue
            print(f"\n  {paint(password, BOLD)}")
            print_analysis(analyze(password, common))
        elif choice == "3":
            words = _ask_int("  Number of words", 5, 2, 32)
            phrase = generate_passphrase(words=words, wordlist=get_wordlist())
            print(f"\n  {paint(phrase, BOLD)}")
            print(paint(f"  {passphrase_entropy(words=words):.0f} bits of entropy", DIM))
            print_analysis(analyze(phrase, common))
        elif choice in ("4", "q", "quit", "exit"):
            print("  Stay safe.\n")
            return 0
        else:
            print("  Pick 1, 2, 3 or 4.\n")


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passguard",
        description="Analyse password strength and generate strong passwords.",
        epilog="Run without arguments for an interactive menu.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # -- check ------------------------------------------------------------- #
    check = subparsers.add_parser("check", help="analyse the strength of a password")
    check.add_argument("password", nargs="?", help="the password (omit to be prompted)")
    check.add_argument("--hidden", action="store_true",
                       help="prompt for the password without echoing it")
    check.add_argument("-v", "--verbose", action="store_true",
                       help="show detected patterns and every attack scenario")
    check.add_argument("--json", action="store_true", help="print the report as JSON")
    check.add_argument("--min-score", type=int, default=60, metavar="N",
                       help="exit with code 1 below this score (default: 60)")
    check.set_defaults(func=command_check)

    # -- gen --------------------------------------------------------------- #
    gen = subparsers.add_parser("gen", help="generate random passwords")
    gen.add_argument("-l", "--length", type=int, default=16, help="length (default: 16)")
    gen.add_argument("-n", "--count", type=int, default=1, help="how many (default: 1)")
    gen.add_argument("--no-lower", action="store_true", help="exclude lowercase letters")
    gen.add_argument("--no-upper", action="store_true", help="exclude uppercase letters")
    gen.add_argument("--no-digits", action="store_true", help="exclude digits")
    gen.add_argument("--no-symbols", action="store_true", help="exclude symbols")
    gen.add_argument("--no-ambiguous", action="store_true",
                     help="exclude look-alike characters such as l, 1, O and 0")
    gen.add_argument("-c", "--copy", action="store_true", help="copy the last one to the clipboard")
    gen.add_argument("--check", action="store_true", help="also analyse the generated password")
    gen.add_argument("-v", "--verbose", action="store_true", help="detailed analysis with --check")
    gen.add_argument("-q", "--quiet", action="store_true", help="print passwords only")
    gen.set_defaults(func=command_gen)

    # -- passphrase -------------------------------------------------------- #
    phrase = subparsers.add_parser("passphrase", help="generate word-based passphrases")
    phrase.add_argument("-w", "--words", type=int, default=5, help="word count (default: 5)")
    phrase.add_argument("-n", "--count", type=int, default=1, help="how many (default: 1)")
    phrase.add_argument("-s", "--separator", default="-", help="separator (default: '-')")
    phrase.add_argument("--capitalize", action="store_true", help="Capitalise Each Word")
    phrase.add_argument("--number", action="store_true", help="append a two-digit number")
    phrase.add_argument("--symbol", action="store_true", help="append a random symbol")
    phrase.add_argument("-c", "--copy", action="store_true", help="copy the last one to the clipboard")
    phrase.add_argument("--check", action="store_true", help="also analyse the passphrase")
    phrase.add_argument("-v", "--verbose", action="store_true", help="detailed analysis with --check")
    phrase.add_argument("-q", "--quiet", action="store_true", help="print passphrases only")
    phrase.set_defaults(func=command_passphrase)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        return interactive()

    try:
        return args.func(args)
    except GeneratorError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        raise SystemExit(130)
