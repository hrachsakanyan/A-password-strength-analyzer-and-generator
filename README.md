# PassGuard

**A password strength analyzer and generator written in pure Python — no dependencies.**

PassGuard tells you how strong a password really is *and why*, then generates a better one.
It works completely offline: nothing you type is stored, logged or sent anywhere.

> 🇦🇲 PassGuard-ը վերլուծում է password-ի ուժգնությունը rule-based մոտեցմամբ (երկարություն,
> character classes, entropy, common-password check) և գեներացնում ուժեղ password-ներ ու
> passphrase-ներ՝ `secrets` մոդուլով։

---

## Features

- **Strength scoring** — a 0–100 score with a `Very Weak → Very Strong` verdict.
- **Concrete feedback** — not "weak password", but *"contains a keyboard pattern: 'fghjkl'"*.
- **Real entropy estimate** — patterns an attacker's tool already knows (dictionary words,
  `abcd`, `1111`, `qwerty`, leetspeak) are charged only the few bits they actually cost.
- **Common-password check** — offline wordlist of the most-used passwords, matched through
  case changes and leetspeak (`p@ssw0rd` is caught as `password`).
- **Honest passphrase grading** — the analyzer reads the same wordlist the generator uses,
  so a five-word passphrase is priced at five word-guesses, not thirty character-guesses.
- **Time-to-crack estimates** for four realistic attack scenarios.
- **Password generator** — length, character classes, and a "no look-alike characters" mode.
- **Passphrase generator** — `otter-canyon-brass-anchor-vault`, from a 1000+ word list.
- **Clipboard copy**, **JSON output**, and a **script-friendly exit code**.
- **61 unit tests**, standard library only.

---

## Installation

Requires Python 3.9+. There is nothing to install.

```bash
git clone https://github.com/<your-username>/passguard.git
cd passguard
python src/main.py
```

---

## Usage

### Interactive mode

```bash
python src/main.py
```

```
  ____               ____                     _
 |  _ \ __ _ ___ ___ / ___|_   _  __ _ _ __ __| |
 | |_) / _` / __/ __| |  _| | | |/ _` | '__/ _` |
 |  __/ (_| \__ \__ \ |_| | |_| | (_| | | | (_| |
 |_|   \__,_|___/___/\____|\__,_|\__,_|_|  \__,_|
   password strength analyzer & generator

  Loaded 358 common passwords and 1,084 passphrase words.

  1) Check a password
  2) Generate a password
  3) Generate a passphrase
  4) Quit
```

### Check a password

```bash
python src/main.py check "Summer2023!"
python src/main.py check --hidden          # prompts without echoing
python src/main.py check "hunter2" -v      # show detected patterns
python src/main.py check "hunter2" --json  # machine readable
```

`Summer2023!` has eleven characters, upper case, lower case, a digit and a symbol.
Most strength meters call it strong. Here is what PassGuard says:

```
  VERY WEAK  19/100
  [######------------------------]

  Length          : 11 characters
  Character types : lowercase, uppercase, digits, symbols
  Entropy         : 15.4 bits (brute-force upper bound 72.1)
  Cracking time   : instantly (offline GPU attack)

  Problems found:
    x Built mostly from known password(s): 'Summer2023'.
    x Looks complex, but only 15 bits of real entropy -- the pattern is predictable.

  How to improve:
    - Make it at least 12 characters -- length beats complexity.
    - Avoid known passwords -- cracking tools start with them.
```

### Generate passwords

```bash
python src/main.py gen                        # 16 chars, all classes
python src/main.py gen -l 24 -n 5             # five 24-character passwords
python src/main.py gen -l 12 --no-symbols     # letters and digits only
python src/main.py gen --no-ambiguous         # skip l/1/I, O/0, S/5 …
python src/main.py gen -l 20 --copy --check   # copy it and analyse it
python src/main.py gen -l 6 --no-lower --no-upper --no-symbols   # a 6-digit PIN
```

### Generate passphrases

```bash
python src/main.py passphrase                       # 5 words, ~50 bits
python src/main.py passphrase -w 6 --capitalize     # Choir-Science-Watch-Tissue-…
python src/main.py passphrase -w 4 -s "." --number  # otter.canyon.brass.vault.07
```

### In scripts

`check` exits with **0** if the password reaches the minimum score and **1** if it does not,
so it drops straight into a shell script or CI job:

```bash
python src/main.py check "$PASSWORD" --min-score 70 --json > report.json || echo "Too weak!"
```

---

## How scoring works

The score starts at 0, earns points from three rules, then loses points to penalties.
The result is clamped to 0–100.

| Rule | Points | Detail |
|---|---|---|
| **Length** | 0 → 40 | 3.5 points per character past the 4th (maxed at ~16 characters) |
| **Variety** | 0 → 30 | lowercase +5, uppercase +8, digits +7, symbols +10 |
| **Entropy** | 0 → 30 | 0.5 points per bit of *estimated* entropy (maxed at 60 bits) |
| *Penalty* | −15 | shorter than 8 characters |
| *Penalty* | −10 | uses only one character class |
| *Penalty* | −15 | a known password covers half the password or more |
| *Penalty* | −10 | built around one dictionary word (`parsley2024`) |
| *Penalty* | −8 each | per pattern type found: sequence, keyboard walk, repetition |
| *Hard cap* | ≤ 10 | the whole password appears in the common-password list |

Then the **entropy ceiling** applies. Length and variety points must never outvote
guessability, so a password cannot score above:

| Estimated entropy | Best possible score |
|---|---|
| under 20 bits | 19 — Very Weak |
| under 28 bits | 39 — Weak |
| under 40 bits | 59 — Fair |
| under 60 bits | 79 — Strong |

This is what stops `P@ssw0rd123` — eleven characters, all four character classes —
from being called strong. It scores **19/100**, because it is worth 17 bits.

| Score | Verdict |
|---|---|
| 80 – 100 | Very Strong |
| 60 – 79 | Strong |
| 40 – 59 | Fair |
| 20 – 39 | Weak |
| 0 – 19 | Very Weak |

### Why the entropy number is lower than you expect

The naive formula `length × log2(alphabet)` says `password1` is worth 46 bits.
An attacker needs about **4**, because `password1` sits near the top of every leaked
password list. PassGuard scans the password left to right and, at each position, asks which
of these is cheapest for an attacker:

| Pattern | Cost charged | Example |
|---|---|---|
| Known password | `log2(rank in the list)` + capitalisation + leetspeak | `password`, `p@ssw0rd` |
| Dictionary word | `log2(size of wordlist)` ≈ 10 bits, whatever the length | `parsley`, `anchor` |
| Character sequence | ~6 bits + `log2(run length)` | `abcdef`, `9876` |
| Keyboard walk | ~7 bits + `log2(run length)` | `qwerty`, `fghjkl` |
| Repetition | cost of one block + `log2(repeat count)` | `aaaa`, `Aa1!Aa1!Aa1!` |
| Anything else | `log2(alphabet)` per character | `qP7!vZ` |

The cheapest reading wins, the costs are added up, and `log2(number of chunks!)` is added
back because the attacker must also guess the order the chunks were assembled in.
Both numbers are shown: the estimate, and the brute-force upper bound.

---

## Security note: `secrets`, not `random`

Every password PassGuard generates comes from Python's [`secrets`](https://docs.python.org/3/library/secrets.html)
module, which draws from the operating system's cryptographic random source.

The `random` module is **not** used anywhere in this project. `random` is a Mersenne
Twister: fast, repeatable, and fine for shuffling a deck in a game — but an attacker who
observes 624 of its outputs can reconstruct its internal state and predict every value it
will ever produce. It is also seeded from the clock, so passwords generated at a guessable
moment are themselves guessable.

```python
import random, secrets

random.choice(alphabet)   # predictable — never for passwords
secrets.choice(alphabet)  # what PassGuard uses
```

The shuffle that hides the guaranteed characters is a Fisher–Yates driven by
`secrets.randbelow`, for the same reason.

Other notes:

- PassGuard **never writes a password to disk** and makes no network calls.
- `--hidden` reads via `getpass`, so the password is not echoed and does not land in your
  shell history. Passing a password as a CLI argument *does* put it in your history — use
  `--hidden` for real ones.
- The clipboard is a shared resource on most systems. `--copy` is convenient, not private.

---

## Project structure

```
passguard/
├── src/
│   ├── main.py                  CLI + interactive menu
│   ├── analyzer.py              scoring, entropy estimation, pattern detection
│   └── generator.py             password and passphrase generation
├── data/
│   ├── common_passwords.txt     ranked common-password list
│   └── wordlist.txt             1000+ words for passphrases
├── tests/
│   ├── test_analyzer.py
│   └── test_generator.py
├── README.md
├── requirements.txt
└── .gitignore
```

---

## Running the tests

```bash
python -m unittest discover -s tests -v
```

```
Ran 61 tests in 0.08s

OK
```

`pytest tests/` works too, if you prefer it.

---

## Limitations

Worth knowing before you trust the number:

- The common-password list ships with a few hundred entries so the repository stays small.
  Drop a bigger list (for example `rockyou.txt`) into `data/common_passwords.txt` — ordered
  most-common first — and the analyzer immediately gets sharper.
- The dictionary only covers passwords, not general English, names, or dates. `Tr0ub4dor&3`
  scores well here but would be cracked by a tool with a full dictionary.
- Time-to-crack numbers assume the attacker is offline with your password hash. A well
  designed site with rate limiting is far more forgiving; a site that stores unsalted MD5
  is far less.

Rule of thumb that survives all of this: **length beats complexity**, and a password
manager beats memorising anything.

---

## Possible next steps

- [ ] tkinter GUI
- [ ] "have I been pwned" k-anonymity lookup (opt-in, online)
- [ ] Password policy presets (NIST 800-63B, corporate minimums)
- [ ] Bulk audit of a CSV export from a password manager

## License

MIT
