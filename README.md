# 🛡️ PassGuard 

### 🔐 A Password Strength Analyzer & Secure Password Generator — Built with Pure Python

**PassGuard** is a privacy-first command-line tool that analyzes **how strong a password really is — and explains why**.

It also generates secure **passwords** and **passphrases** using Python's cryptographically secure `secrets` module.

🔒 **100% Offline** · 🚫 **No Dependencies** · 🐍 **Pure Python** · 🧪 **61 Unit Tests**


> ⚠️ **Privacy First:** Nothing you type is stored, logged, uploaded, or sent anywhere.

---

## ✨ Features
 
| Feature                          | Description                                                       |
| -------------------------------- | ----------------------------------------------------------------- |
| 💪 **Strength Scoring**          | 0–100 score with `Very Weak → Very Strong` verdict                |
| 🔍 **Smart Feedback**            | Explains *why* a password is weak instead of simply saying "weak" |
| 🧠 **Entropy Estimation**        | Detects predictable patterns attackers already know               |
| 🔑 **Common Password Check**     | Detects common passwords, case changes, and leetspeak             |
| 📝 **Passphrase Analysis**       | Evaluates passphrases based on word-level guessing                |
| ⏱️ **Crack Time Estimates**      | Estimates attack time across four realistic scenarios             |
| 🎲 **Secure Password Generator** | Generates cryptographically secure passwords                      |
| 🦦 **Passphrase Generator**      | Creates memorable multi-word passphrases                          |
| 📋 **Clipboard Support**         | Copy generated passwords directly to clipboard                    |
| 📦 **JSON Output**               | Machine-readable output for scripts and automation                |
| 🤖 **Script-Friendly**           | Exit codes make PassGuard suitable for CI and shell scripts       |
| 🧪 **61 Unit Tests**             | Thoroughly tested with Python's standard library                  |
| 📴 **Fully Offline**             | No network requests, no tracking, no data collection              |

---

# 🚀 Installation

### Requirements

* 🐍 Python **3.9+**
* 📦 No external dependencies required

Clone the repository:

```bash
git clone https://github.com/<your-username>/passguard.git
cd passguard
```

Run PassGuard:

```bash
python src/main.py
```

That's it. 🎉

---

# 🖥️ Usage

## 🎯 Interactive Mode

Start PassGuard without arguments:

```bash
python src/main.py
```

You'll see an interactive menu:

```text
  ____               ____                     _
 |  _ \ __ _ ___ ___ / ___|_   _  __ _ _ __ __| |
 | |_) / _` / __/ __| |  _| | | |/ _` | '__/ _` |
 |  __/ (_| \__ \__ \ |_| | |_| | (_| | | | (_| |
 |_|   \__,_|___/___/\____|\__,_|\__,_|_|  \__,_|

        🔐 password strength analyzer & generator

  📚 Loaded 358 common passwords
  📖 Loaded 1,084 passphrase words

  1) 🔍 Check a password
  2) 🔐 Generate a password
  3) 🦦 Generate a passphrase
  4) 🚪 Quit
```

---

## 🔍 Check a Password

Analyze a password:

```bash
python src/main.py check "Summer2023!"
```

For sensitive passwords, use hidden input:

```bash
python src/main.py check --hidden
```

Show detected patterns:

```bash
python src/main.py check "hunter2" -v
```

Get machine-readable JSON output:

```bash
python src/main.py check "hunter2" --json
```

### Example 

A password like:

```text
Summer2023! 
```

looks strong to many traditional password meters because it contains:

* ✅ Uppercase letters
* ✅ Lowercase letters
* ✅ Numbers
* ✅ Symbols
* ✅ 11 characters

But PassGuard looks deeper:

```text
🔴 VERY WEAK  19/100
[######------------------------]

Length          : 11 characters
Character types : lowercase, uppercase, digits, symbols
Entropy         : 15.4 bits
Brute-force     : 72.1 bits
Cracking time   : instantly (offline GPU attack)

❌ Problems found:

   • Built mostly from known password(s): 'Summer2023'
   • Looks complex, but has only ~15 bits of real entropy
   • The pattern is predictable to modern cracking tools

💡 How to improve:

   • Make it at least 12+ characters
   • Avoid known passwords and common patterns
   • Prefer a randomly generated password or passphrase
```

> 💡 **Key idea:** A password can look complicated to a human while still being easy for an attacker to guess.

---

# 🔐 Generate Secure Passwords

Generate a default 16-character password:

```bash
python src/main.py gen
```

Generate five 24-character passwords:

```bash
python src/main.py gen -l 24 -n 5
```

Generate a 12-character password without symbols:

```bash
python src/main.py gen -l 12 --no-symbols
```

Avoid ambiguous characters such as `l/1/I`, `O/0`, `S/5`:

```bash
python src/main.py gen --no-ambiguous
```

Generate, copy, and analyze a password:

```bash
python src/main.py gen -l 20 --copy --check
```

Generate a 6-digit PIN:

```bash
python src/main.py gen \
  -l 6 \
  --no-lower \
  --no-upper \
  --no-symbols
```

---

# 🦦 Generate Passphrases

Generate a 5-word passphrase:

```bash
python src/main.py passphrase
```

Example:

```text
otter-canyon-brass-anchor-vault
```

Generate a 6-word passphrase with capitalization:

```bash
python src/main.py passphrase -w 6 --capitalize
```

Use a custom separator and add a number:

```bash
python src/main.py passphrase -w 4 -s "." --number
```

Example:

```text
Otter.Canyon.Brass.Vault.07
```

> 🧠 Passphrases are often easier to remember while still providing strong security when generated randomly.

---

# 🤖 Use PassGuard in Scripts 

The `check` command returns:

* `0` → Password meets the minimum score
* `1` → Password does not meet the minimum score

This makes PassGuard useful in shell scripts and CI pipelines.

```bash
python src/main.py check "$PASSWORD" \
  --min-score 70 \
  --json > report.json \
  || echo "⚠️ Password is too weak!"
```

---

# 🧠 How Password Scoring Works

PassGuard calculates a score from **0 to 100**.

The score combines:

### 📏 Length

Longer passwords receive more points.

### 🔤 Character Variety

The analyzer considers:

* lowercase letters
* uppercase letters
* digits
* symbols

### 🧮 Estimated Entropy

PassGuard tries to estimate how difficult the password would be for an attacker to guess.

### ⚠️ Pattern Penalties

Points are removed for predictable patterns such as:

* common passwords
* dictionary words
* keyboard walks
* character sequences
* repeated blocks
* predictable substitutions
* leetspeak

---

## 📊 Scoring Rules

| Rule                          |        Points | Description                            |
| ----------------------------- | ------------: | -------------------------------------- |
| 📏 **Length**                 |        0 → 40 | Longer passwords score higher          |
| 🔤 **Variety**                |        0 → 30 | Rewards different character classes    |
| 🧮 **Entropy**                |        0 → 30 | Rewards estimated unpredictability     |
| ⚠️ **Short Password**         |           −15 | Password shorter than 8 characters     |
| ⚠️ **Single Character Class** |           −10 | Uses only one character type           |
| 🔑 **Known Password**         |           −15 | Known password covers half or more     |
| 📖 **Dictionary Word**        |           −10 | Built around one dictionary word       |
| 🔁 **Pattern Detection**      |       −8 each | Sequence, keyboard walk, repetition    |
| 🛑 **Common Password**        | Hard cap ≤ 10 | Entire password appears in common list |

---

# 🏆 Password Strength Levels

|           Score | Verdict     |
| --------------: | ----------- |
| 🟢 **80 – 100** | Very Strong |
|  🔵 **60 – 79** | Strong      |
|  🟡 **40 – 59** | Fair        |
|  🟠 **20 – 39** | Weak        |
|   🔴 **0 – 19** | Very Weak   |

---

# 🧠 Why Entropy Matters 

Traditional password meters often use a simple formula:

```text
length × log₂(alphabet size)
```

This can dramatically overestimate the strength of predictable passwords.

For example:

```text
password1
```

may look like a combination of letters and numbers.

But attackers already know that:

* `password`
* `password1`
* `Password1`
* `P@ssw0rd`

are extremely common patterns.

PassGuard therefore tries to identify patterns that real attackers would prioritize.

| Pattern               | Estimated Cost                 | Example                |
| --------------------- | ------------------------------ | ---------------------- |
| 🔑 Known Password     | `log₂(rank)` + transformations | `password`, `p@ssw0rd` |
| 📖 Dictionary Word    | `log₂(wordlist size)`          | `parsley`, `anchor`    |
| 🔢 Character Sequence | ~6 bits + run length           | `abcdef`, `9876`       |
| ⌨️ Keyboard Walk      | ~7 bits + run length           | `qwerty`, `fghjkl`     |
| 🔁 Repetition         | Block cost + repeat count      | `aaaa`, `Aa1!Aa1!`     |
| 🎲 Random Characters  | `log₂(alphabet)` per character | `qP7!vZ`               |

The cheapest interpretation is selected because that is the path an attacker is most likely to exploit.

---

# 🔒 Security: `secrets`, Not `random`

PassGuard uses Python's cryptographically secure:

```python
import secrets

secrets.choice(alphabet)
```

It does **not** use:

```python
import random

random.choice(alphabet)
```

The `random` module is designed for simulations and general-purpose randomness, not password generation.

PassGuard uses:

* 🔐 `secrets.choice()`
* 🔐 `secrets.randbelow()`
* 🔀 Secure Fisher–Yates shuffling

This ensures generated passwords rely on the operating system's cryptographically secure random source.

---

# 🛡️ Privacy & Security Notes

PassGuard is designed with privacy in mind.

### 🔒 No Password Storage

PassGuard does not write passwords to disk.

### 🌐 No Network Requests

The application works completely offline.

### 🚫 No Tracking

No analytics. No telemetry. No external services.

### 🙈 Hidden Input

Use:

```bash
python src/main.py check --hidden
```

to enter a password without displaying it on screen.

### ⚠️ CLI Arguments

Be careful when passing passwords directly:

```bash
python src/main.py check "MyPassword123!"
```

Depending on your shell and system configuration, command history may retain the password.

For real passwords, prefer:

```bash
python src/main.py check --hidden
```

### 📋 Clipboard Warning

The clipboard is a shared resource on most systems.

The `--copy` option is convenient, but clipboard contents may be accessible to other applications.

---

# 🗂️ Project Structure

```text
passguard/
│
├── 📁 src/
│   ├── 🐍 main.py
│   │   └── CLI + interactive menu
│   │
│   ├── 🧠 analyzer.py
│   │   └── scoring, entropy estimation, pattern detection
│   │
│   └── 🔐 generator.py
│       └── password & passphrase generation
│
├── 📁 data/
│   ├── 🔑 common_passwords.txt
│   │   └── ranked common-password list
│   │
│   └── 📖 wordlist.txt
│       └── 1,000+ words for passphrases
│
├── 📁 tests/
│   ├── 🧪 test_analyzer.py
│   └── 🧪 test_generator.py
│
├── 📄 README.md
├── 📦 requirements.txt
└── 🚫 .gitignore
```

---

# 🧪 Testing

PassGuard includes **61 unit tests**.

Run all tests with:

```bash
python -m unittest discover -s tests -v
```

Or with pytest:

```bash
pytest tests/
```

Expected result:

```text
Ran 61 tests in 0.08s

OK
```

✅ All core password analysis and generation logic is covered by automated tests.

---

# ⚠️ Limitations

PassGuard is designed as an educational and practical password-analysis tool, but its score should not be treated as an absolute measure of real-world security.

### 📚 Limited Common Password List

The repository contains a relatively small list to keep the project lightweight.

You can replace it with a larger list such as `rockyou.txt` to improve detection.

### 📖 Limited Dictionary

The dictionary does not cover every:

* English word
* Name
* Date
* Cultural reference
* Personal information

A password that scores well may still be vulnerable to a more sophisticated attacker.

### ⏱️ Crack Time Estimates

Crack-time estimates assume an **offline password-hash attack**.

Real-world online attacks are often limited by:

* rate limiting
* account lockouts
* MFA
* CAPTCHA
* monitoring

The security of a password also depends heavily on how the service stores it.

---

# 💡 Security Takeaways

> 🔐 **Length beats complexity.**

> 🎲 **Randomly generated passwords are stronger than predictable human-created passwords.**

> 🔑 **A password manager is usually better than memorizing dozens of passwords.**

> 🛡️ **Use unique passwords for every account.**

> 🔐 **Enable Multi-Factor Authentication (MFA) whenever possible.**

---

# 🚀 Possible Next Steps

The project can be extended with:

* [ ] 🖥️ **Tkinter GUI**
* [ ] 🌐 **Have I Been Pwned k-anonymity lookup** *(opt-in, online)*
* [ ] 📋 **Password policy presets**
* [ ] 📊 **Password strength visualization**
* [ ] 📁 **Bulk password audit from CSV**
* [ ] 🔐 **Password manager integration**
* [ ] 🧪 **More advanced attack-model simulation**

---

# 📄 License

Released under the **MIT License**.

---

<div align="center">

### 🔐 Build Better Passwords. Understand Your Security.

**PassGuard** — Analyze. Generate. Protect.

Made with 🐍 Python and 🔐 `secrets`

</div>
