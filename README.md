

# PyGuard

PyGuard is a secure Python code obfuscator that transforms your source code into a protected form while maintaining functionality.
## Features

- 🔒 Multi-layer code protection
- 🚀 Real-time obfuscation
- 📋 One-click copy to clipboard
- 🎯 Browser-based - no installation needed
- 🛡️ Multiple obfuscation techniques:
  - XOR encryption
  - Base64 encoding
  - String reversing
  - Random chunking
  - Runtime protection
  - Built-in function protection

## Official PyGuard Website
You can access and use the PyGuard at [https://pyguard.akean.dev](https://pyguard.akean.dev)

## Running PyGuard Locally

```bash
# Clone the repository
git clone https://github.com/yourusername/pyguard.git

# Navigate to project directory
cd pyguard

# Install dependencies
npm install

# Start development server
npm run dev
```

## Usage

1. Visit the PyGuard web interface
2. Paste your Python code into the text area
3. Click "Obfuscate" to transform your code
4. Use the "Copy to Clipboard" button to copy the obfuscated result

## Stub size and runtime

The v5.2 pipeline compresses both the embedded interpreter source (raw
deflate, ~17% of the original) and the user IR (raw deflate with `-15`
wbits on the Python side). It also emits the interpreter as a one-shot
`zlib.decompress(...).exec(...)` prelude instead of inlining it as source
text. The net effect across the 15 representative test cases:

| | stage1+stage2 | stub lines | cold exec |
|---|---|---|---|
| v5.0 | plaintext interpreter inlined | ~1470 | ~320 ms |
| v5.1 | plaintext interpreter inlined | ~13 500 | ~320 ms |
| v5.2 | compressed interpreter + compressed IR + list-form | ~285 | ~60 ms |

"Cold exec" is `time python3 stub.py` on `01_print.py` on the reference
dev machine; the dominant cost is Python startup, not the stub itself.
On the 15-case suite the total stub line count dropped from 9 755 (v5.1)
to 4 298 (v5.2) — a 2.3× reduction — and the largest stub fits under
76 KB. Regenerate with `node scripts/gen-v5-stub.mjs <source.py>`.

## Security: what PyGuard actually defends against

PyGuard is an **obfuscator**, not an encryptor. The threat model it addresses is
raising the cost for a human or LLM that wants to read your source, not
cryptographically preventing recovery. This section documents exactly what each
version stops and where it fails, because every claim stronger than that is a
lie.

**Fundamental limit.** No pure-Python self-decoding obfuscator can ever be
unbreakable. The target machine runs the stub with the full Python runtime, so
the attacker can install audit hooks, patch stdlib modules, install `settrace`
handlers, walk frame locals, and dump any object the interpreter touches. The
stub must eventually hand the real program to CPython to execute; at that
moment, by construction, the real program is in memory and observable. The
question is not "can it be recovered" but "how much work".

### The attack ladder

All attacks live in `tests/pentest/`. The scoreboard is
`tests/pentest/run_scoreboard.sh` — it classifies each attack against each of
15 representative stubs as **PWNED** (source fingerprint leaked), **HELD**
(attack ran but recovered nothing), or **CRASH**.

| # | Attack | v4 | v5 | v5.1 | v5.2 |
|---|---|---|---|---|---|
| 4 | Static AST/string scan | HELD | HELD | HELD | HELD |
| 5 | LLM deobfuscation of the stub text | HELD | HELD | HELD | HELD |
| 6 | AST surgery on the stub | HELD | HELD | HELD | HELD |
| 7 | Expression walker | HELD | HELD | HELD | HELD |
| 8 | PEP 578 audit hook on `compile` | **PWNED** | HELD | HELD | HELD |
| 9 | `sys.settrace` source dumper | **PWNED** | HELD | HELD | HELD |
| 11 | `json.loads` monkey-patch (IR hook) | n/a | **PWNED** | HELD | HELD |
| 12 | `settrace` + frame-local key-based IR scan | n/a | **PWNED** | **PWNED** | HELD |
| 13 | `settrace` + structural shape-based IR scan | n/a | **PWNED** | **PWNED** | **PWNED** |

### What each layer earned

- **v4 → v5**: v4's final stage called `compile(user_source, ...)`, so any
  attacker with a PEP 578 audit hook (attack 8) or a Python-level tracer
  (attack 9) received the user source in a single event. v5 replaces that
  `compile` with a generic AST-walking interpreter plus an encrypted IR blob.
  The stub never compiles user source — only the interpreter source and
  ciphertext. Attacks 8 and 9 now see only the interpreter. Cost to the
  attacker: write a v5-specific loader instead of reusing the v4 dumper.
- **v5 → v5.1**: v5 still decrypted the IR JSON with `json.loads`. Attack 11
  monkey-patches `json.loads` in one line and captures the full IR dict, which
  a trivial reverse-lifter (`tests/pentest/_v5_lifter.py`) turns back into
  Python source. v5.1 parses the IR with `_pg_parse_json`, a hand-rolled
  recursive-descent parser that lives inside the embedded interpreter source.
  There is no stdlib entry point for attack 11 to hook. Cost to the attacker:
  cannot reuse the one-line `json.loads` hook.
- **v5.1 → v5.2**: Attack 12 defeated v5.1 by (1) monkey-patching
  `sys.gettrace`/`sys.getprofile` to return `None` (which satisfies the stub's
  Python-level anti-trace check while the real C-level tracer keeps firing),
  (2) installing a `sys.settrace` handler that on every `return` event scans
  `frame.f_locals` for a dict with the IR shape `{tree, strings, consts}`, and
  (3) raising a `BaseException` sentinel to short-circuit the stub as soon as
  the IR is captured. v5.2 changes two things simultaneously to raise the
  cost of this hook: the top-level IR is encoded as a **JSON list**
  `[strings, consts, tree]` (so attack 12's `isinstance(v, dict) and
  {'tree','strings','consts'} <= v.keys()` check fails at the first
  `isinstance`), and the embedded interpreter source is **raw-deflate
  compressed** before base64, which shrinks the stub by ~3× (a case-01 stub
  goes from ~216 KB to ~67 KB) and hides the interpreter keywords from naive
  string scanners. Attack 12 is now HELD on all 15 stubs.
- **v5.2 is still breakable.** Attack 13 generalises attack 12 by dropping
  the *key-based* IR match and using **two structural shape heuristics**
  that do not rely on any literal field name: (A) a top-level list of length
  3 whose shape is `[list, list, dict-with-'op'-in-KNOWN_OPS]`, and (B) a
  standalone dict with `op == 'Module'`. Heuristic C then scans the
  returning frame's `f_locals` directly for the triple, which catches the
  intermediate list the moment `_pg_parse_json` returns. On the current v5.2
  build, attack 13 PWNs all 15 stubs in ~3 seconds each and is implemented in
  ~150 lines (`tests/pentest/attack13_v5_structural_walk.py`). The takeaway:
  any hardening that merely renames or re-shapes the IR while still keeping
  it live as Python data in a frame is dressing, not a defence.

### How to read this

The progression attack 11 → v5.1 → attack 12 → v5.2 → attack 13 is the
point. Each hardening round raised the bar — from "one-line stdlib patch"
to "defeat the anti-trace check plus a key-based frame-local scan" to
"defeat both and use a shape-based scan that ignores field names" — but
none of them made the obfuscator unbreakable and none of them ever will. If
you need cryptographic guarantees that your source cannot be recovered, you
need a different tool (native compilation, a server-side API, or a hardware
enclave). If you need to make casual recovery expensive, PyGuard raises
that cost and this table tells you exactly how far.

After every hardening round we write a new attack. If the latest PyGuard
release ships with a scoreboard where every attack is HELD, either the
scoreboard is out of date or the next attack has not been written yet.

## Contributing

[(Back to top)](#table-of-contents)

Your contributions are always welcome! Feel free to fork this project and work on it.

## License

[(Back to top)](#table-of-contents)

Copyright © 2025 by InsanelyAvner.

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
