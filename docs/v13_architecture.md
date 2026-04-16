# v13 architecture

Scope of this document: the register-machine-VM obfuscation family in
`lib/v5/v13/`. Current state and forward plan, after three red-team
rounds.

## Where v13 stands right now

Three stub shapes have been built:

- `v13.0` — gated stub with a local compare (`OP_EQ` + `OP_JIFZ`).
  PWN'd by A15 (force-branch, regex one-liner) and A17 (static VM
  simulation, ~140 lines, recovers password and flag without running
  the stub).
- `v13.1` — KDF-gated stub. No local compare, no branch on secrets,
  unconditional `decrypt = scrypt(input, salt) XOR ct; print`. A15
  and A17 no longer extract the flag; A21 reduces the entire stub
  to 10 lines of equivalent Python without needing the password.
- `v13.2` — encrypted-VM bootstrap. Stage-0 plaintext is only the
  bootstrap (~50 LOC); the VM runtime and the assembled program
  both live inside scrypt-encrypted blobs. A15/A16/A17/A18/A19/A21
  all fail to begin because the structures they parse (handlers,
  `_PAYLOAD`, `OP_*` constants) are not in the stub at all. See
  "Measurements for v13.2" below. The security bound is now
  password entropy × scrypt cost (A24). The obfuscator is not
  providing the security; the KDF and the password are.

v13.1 fixed the specific bugs v13.0 had. It is not an obfuscator.
A21 is evidence: the stub's program structure (scrypt → XOR → print),
its constants (salt, ciphertext), and its external calls (`input`,
`print`) are all trivially recoverable in bulk by pattern-matching
plaintext VM handlers. The only thing that is not recoverable is the
flag plaintext, and that is protected by scrypt, not by the VM.

The attacker's total cost to recover the flag against v13.1 is:

1. ~1 human-hour to write/run A21-shape tooling, once. (Or zero
   hours — A21 is already written and reused.)
2. scrypt × dictionary cost for the password. At N=2^14, r=8, a
   rented RTX 4090 does rockyou in ~23 min for ~$1.

v13.1's contribution to this total is ~1 hour of human time, *once*,
amortised across all v13.1 stubs anyone ever ships. That is not an
obfuscator; it is a speed bump.

## The actual threat model for an obfuscator

A challenge obfuscator must make *semantic recovery* expensive, not
just flag recovery. If an attacker can mechanically emit an equivalent
program, they understand the machine and have won regardless of whether
any particular secret is in it.

The success metric is therefore:

> **Time for an analyst (with A17/A21-class tooling) to produce an
> equivalent program from a fresh stub** — measured in human-hours per
> build — should be bounded from below by the challenge's intended
> password-cracking cost.

If a build crumbles to 10 lines of Python in one hour of analyst time,
any scrypt parameters below ~2^30 are a lie.

## Design principles the v14 plan commits to

These replace the informal grab-bag the M0/M1 plan rested on.

1. **The attacker can read every byte of the stub.** The stub must
   therefore encode its program *and* its runtime in ways where
   reading the bytes doesn't give you the semantics. No plaintext
   `OP_SCRYPT` handler. No stable `hashlib.scrypt` call site. No
   opcode whose value is the same in two different builds.

2. **Execution is required to learn structure.** Static simulation
   (A17/A21) must fail to reveal handler semantics. Each stage of
   the stub decrypts the next stage using keys derived from executing
   the current stage correctly. A static simulator that didn't run
   the whole machine only sees a byte stream of encrypted next
   stages.

3. **Correct password is required to learn program structure.** Wrong
   password → wrong scrypt output → wrong key-schedule inputs → wrong
   handler decryption → the "VM" executes handlers that are, by
   construction, indistinguishable-from-random bytecode and produce
   garbage output. No branch, no check, no crash. The attacker cannot
   dictionary-attack offline *and* recover program structure; they
   must do both at once in the inner loop, paying the full scrypt cost
   per guess.

4. **Per-build diversification is structural, not cosmetic.** Two
   builds differ in: opcode values, operand permutation, slot
   layout, handler body structure, which primitive is which, and
   what the keystream function is. An analyst's first-build work
   does not reduce second-build work to below ~30 min.

5. **No identifiable cryptographic primitives.** `hashlib.scrypt`
   as a visible call in any handler is a billboard pointing at the
   KDF. The KDF is instead assembled at runtime from hashlib
   constructors and repeated `update`/`digest` patterns that
   *compute* scrypt without containing the string `scrypt` or a
   function that pattern-matches it.

6. **Decoys must be indistinguishable from reality on wrong keys.**
   Wrong-password execution deterministically enters handlers that
   produce plausible-looking random output — never "Access denied",
   never an exception, never a timing anomaly. The attacker's oracle
   is `FLAG{` in the output bytes and nothing else.

7. **Attacks are written BEFORE each version is claimed finished.**
   For every version v13.x, the defining question is: which A-series
   attack fails on this version that succeeded on v13.(x-1)? Until
   that attack is written and runs, the version is not done.

8. **The doc does not call anything "held" or "strong" or "secure".**
   Outcomes are recorded as one of: `pwn`, `partial` (some data
   recovered but not the thing the attack was supposed to get),
   `no-extract` (attack ran and produced nothing of value), `scoped
   out` (attack's premise doesn't apply; not evidence of strength).

## Version plan (granular)

Each step is a small, demonstrable slice with one attack. No jumps
labelled "M2" covering twelve changes at once.

| Ver    | Change                                                                 | Attack to write          | Success = attack outcome |
|--------|------------------------------------------------------------------------|---------------------------|--------------------------|
| v13.0  | Gated stub with local compare (baseline)                               | A15 force-branch, A17 sim | (historical: pwn)         |
| v13.1  | KDF-gated; no local compare; unconditional decrypt (current)           | A21 semantic recovery     | (historical: pwn)         |
| v13.2  | Encrypted-VM bootstrap. Per-build opcode permutation *and* the entire VM source + assembled program live inside two scrypt-encrypted blobs. Stage-0 plaintext is only the bootstrap (~50 LOC). Wrong-password output is deterministic pseudo-random hex of the same shape as a success run. *(This is the plan's old v13.2+v13.9 collapsed into one version — see "Plan revision after v13.2" below.)* | A22 static-leakage survey; A23 exec-replace / instrumentation; A24 v13.2-native brute-force economics; re-run A15/A16/A17/A18/A19/A21. | See "Measurements for v13.2" below. |
| v13.3  | Chained handler decryption. Handler N's body is ciphertext under key = SHA-256(master_key ‖ trace-digest-so-far). An attacker who pays the KDF once still doesn't get all handlers — they only get handlers reachable along traces they actually execute. | A25: run with correct password, dump all decrypted handlers along one trace; then A21-style recover from that trace. | Expect pwn when attacker has correct password and a reachable trace. Goal is to make static extraction (without password) still fail, and to make "pay KDF once, dump everything" incomplete. |
| v13.4  | KDF assembled from stdlib primitives; no literal `hashlib.scrypt` call appears in the bootstrap. Computes scrypt via PBKDF2+Salsa20 building blocks without containing the string `scrypt`. | A26: pattern-free KDF extractor — fingerprint the call by timing/memory rather than string match. | Expect partial: A26 can identify the KDF family but still needs A27+ to extract program. |
| v13.5  | Handler polymorphism. N>1 distinct handler bodies per semantic op; dispatch picks by state. Defeats "one body per op" clustering. | A27: enumerate decrypted handler bodies, cluster them semantically, merge. | Expect pwn when attacker has the password; measure how much it slows A21. |
| v13.6  | Password-entangled wrong-path execution. Wrong password → wrong master_key → handler bodies decrypt to executable-but-nonsense Python that still runs and still produces output bytes (rather than the current sha256 hex fallback). | A28: brute force + per-guess handler validity check. Must pay full scrypt per guess; no shortcut oracle from static analysis. | Expect: correctness oracle is no longer `compile()` — wrong-password output is also valid Python. Oracle must then be "output starts with FLAG{" or similar. Brute-force cost ≥ A24. |
| v13.7  | State-dependent operand permutation. An operand byte at pc₁ and pc₂ for the same semantic argument is encoded differently, as a function of state at that pc. Defeats "find all LDI operands by pattern." | A29: state-aware operand-classifier after per-build reverse. | Expect pwn per-build; measure per-build analyst time. Goal: >2h per build. |
| v13.8  | Decoy handlers for wrong-password execution. Handlers that corrupt state into printable-looking-but-wrong bytes without exception, timing anomaly, or control-flow divergence. | A30: differential / oracle-search for any distinguisher between correct and wrong execution paths. | Expect no-extract: diff should be indistinguishable from pseudorandom. |
| v13.9  | ~~Multi-stage self-decrypt bootstrap.~~ **Landed early in v13.2.** The encrypted-VM bootstrap already collapses stage 0 (plaintext) + stage 1 (VM, encrypted) into the v13.2 design. This row remains for historical traceability. | — | (subsumed by v13.2) |
| v13.10 | Per-build state-model variation (slot count, keystream function, snapshot width, dispatch style). Closes cross-build automation. | A31: build two stubs, try to run a single attack against both. | Expect per-build redo. Target: attack built for build A fails on build B. |

This is ten numbered, auditable steps. Each has a concrete attack
whose outcome determines whether the step is finished. No "security
proofs" — only measurements.

## Measurements for v13.2

All numbers below are reproducible: build `/tmp/v13_2.py` via
`python3 -m lib.v5.v13.build_v13_2_stub /tmp/v13_2.py`, then run the
attacks from `tests/pentest_v13_2/attacks/`. Measurements reflect the
build with seed `ab12a51a17b8825bd9605d8ef7dee2406e7cbedf10bad9a08e8704c301ba79bc`
on this workstation; numbers that depend on the build seed (blob
sizes, opcode bytes) will differ slightly across builds.

### Retest of v13.1-era attacks against v13.2

| Attack | What it did on v13.1 | Outcome on v13.2 |
|--------|----------------------|-------------------|
| A15 force-branch    | regex-patched `OP_JIFZ` handler      | `no-extract`: JIFZ handler source not present in stub (encrypted). |
| A16 trajectory tap  | instrumented `OP_XAB` handler         | `no-extract`: OP_XAB handler source not present. |
| A17 static VM sim   | simulated VM from `_PAYLOAD` literal  | `no-extract`: `_PAYLOAD` variable absent from stub; attack cannot begin. |
| A18 scrypt brute    | brute-forced `_PAYLOAD`-shaped layout | `no-extract` as-written; the economics transfer to v13.2 via A24 (below). |
| A19 scrypt patch    | patched `OP_SCRYPT` body              | `no-extract`: no `OP_SCRYPT` symbol in stub. |
| A21 semantic recovery | reduced stub to 10 lines of Python  | `no-extract`: `_PAYLOAD` not found; classifier has no handler bodies to walk. |

The common cause: v13.1 leaked enough structure in plaintext for
every one of these attacks to begin. v13.2 does not. That is not a
claim that v13.2 is strong — it is the statement that these
*particular* attacks' premises no longer apply.

### v13.2-native attacks

**A22 — static leakage survey** (`tests/pentest_v13_2/attacks/a22_static_leakage.py`):

- `OP_*` opcode symbols visible in stub: **0**.
- `def run(` / `_mask(` / `_state_snapshot` references: **0**.
- Handler-body patterns (`state[dst]`, `bytes(c ^ `, etc.) found: **0**.
- Remaining plaintext leaks: `hashlib.scrypt` (1 occurrence), `surrogateescape` (2 occurrences). Both are functional requirements of the stage-0 bootstrap.
- VM blob: 9027 bytes, chi²=271.7, H=7.978 bits/byte (ideal: chi²≈255, H=8.0).
- Program blob: 333 bytes, chi²=259.7, H=7.343 bits/byte (small-sample noise floor).

Interpretation: a static-only attacker sees the bootstrap + two
high-entropy blobs and nothing else. No semantic structure is
statically recoverable. The blobs have no exploitable non-uniformity.

**A23 — exec-replace / instrumentation** (`a23_exec_replace.py`):

Patches the bootstrap to write `vm_src` and `prog` to disk instead of
`exec`'ing them, then runs the patched stub with both wrong and right
passwords.

- Wrong password: `vm_src` = 9027 uniform-random bytes (chi²=259.9, H=7.979), does not compile as Python; `prog` = 333 uniform-random bytes. Attacker gains nothing.
- Right password: `vm_src` compiles (H=4.383, chi²=290725), 14 `OP_*` constants visible; `prog` decrypts to the structured program stream.

Interpretation: instrumentation does not move the security line.
The password-or-nothing property holds: without it, the dumped blobs
are indistinguishable from noise; with it, the bootstrap's own output
already contains the flag, so the VM-source dump is redundant.

**A24 — v13.2-native brute-force economics** (`a24_scrypt_brute_v13_2.py`):

Builds a minimal brute-force loop over the statically-visible
`_SALT, _N, _R, _P, _DK, _NVM, _VMC` parameters. Per-guess work:
one `scrypt`, one XOR, one `compile()`.

- Throughput on this workstation (single CPU core): **43.6 guesses/s**.
- Correctness oracle: `compile(vm_plain, ..., "exec")` succeeds iff the guess is right. False positives in 4-wrong-guess sample: **0/4**.
- Oracle cost ≈ KDF cost (scrypt dominates); the compile step adds no meaningful overhead.
- Extrapolated wall-clock (from measured 43.6 H/s/core, published GPU hashcat figures for scrypt-N=16384):

  | Dictionary   | 1 core  | 16 cores | RTX 4090 (~10 kH/s) | 8× H100 (~100 kH/s) |
  |--------------|---------|----------|----------------------|----------------------|
  | rockyou (14M) | 89.3 h | 5.6 h    | 0.4 h (~23 min)     | <3 min              |
  | 1B guesses   | 6376 h  | 398 h    | 27.8 h              | 2.8 h               |
  | 10B guesses  | 63759 h | 3985 h   | 278 h               | 27.8 h              |

Interpretation: v13.2's security bound is password entropy × scrypt
cost, with a cheap correctness oracle. The VM design and the
encrypted-bootstrap architecture do not add per-guess work beyond one
XOR and one `compile()`. If the password is in rockyou, a single
consumer GPU breaks v13.2 in under 30 minutes. If the password has
60+ bits of true entropy, brute force is impractical. **The
obfuscator is not providing the security; the KDF and the password
are.** This is the same honest statement the red-team critique
demanded.

### What v13.2 does *not* fix

- The bootstrap still contains a literal `hashlib.scrypt(...)` call.
  Any attacker writing v13.2-aware tooling starts there. Closing this
  requires computing scrypt from primitives without naming it
  (planned: v13.4).
- `_SALT`, `_N`, `_R`, `_P`, `_DK`, nonces, and blob sizes are all
  statically visible. That is structurally required for any
  password-gated scheme; the only defence is the KDF cost parameter.
- The correctness oracle is essentially free. Raising KDF cost is the
  only knob that affects brute-force economics.
- There is no claim of resistance to dynamic analysis, memory
  inspection, or an attacker who has the password.

## Plan revision after v13.2

The original plan listed v13.2 as "per-build opcode permutation only"
and v13.9 as "multi-stage self-decrypt bootstrap". After running A21
against v13.1 and noting that opcode permutation alone leaves every
handler body readable — so A22-as-originally-planned (AST-shape
classifier) would still pwn — these two versions were collapsed into
the v13.2 above. The remaining granular steps (v13.3–v13.10) are
reconsidered below and still *predict*, not measure.

- **v13.3** — Handler polymorphism + chained handler decryption. The
  fact that v13.2 hides the entire VM behind one KDF gate means an
  attacker who pays once sees all handlers. v13.3 should make
  handler decryption depend on execution trace so that static dump
  after one KDF pay-off is still incomplete.
- **v13.4** — Scrub the literal `hashlib.scrypt` call from the
  bootstrap. Assemble the KDF from primitives. Attack: A24-analogue
  that has to identify the KDF family without a string match.
- **v13.5+** — Unchanged from the prior table, except they now ride
  on top of a v13.2 that has already closed the static-only attack
  surface, so the attacks each target a specific remaining leak.

## What this plan will *not* claim

- It will not claim v13 resists process-level debugging. `py-spy`,
  `pdb`, `gdb`, and memory dumps on the CPython process can observe
  any Python value in flight. That is a property of running Python;
  no source-level design fixes it.
- It will not claim resistance to weak-password brute force. If a
  password is in the attacker's distribution, the challenge fails
  regardless of the VM. The obfuscator's only job is to not make
  that brute-force job *easier*.
- It will not claim v13.10 is the end. After v13.10, the next pass
  will be specified by whichever attack is cheapest at that point,
  not by a predetermined roadmap.
- It will not call any version "secure", "strong", "held", or
  "unbreakable".

## What "done" means per version

A version is done when:

1. The change is implemented in `lib/v5/v13/` and builds a stub.
2. A new attack targeting that version's new defence is written in
   `tests/pentest_v13/attacks/`.
3. That attack has been run against both v13.(x-1) and v13.x, with
   both outcomes recorded in this doc's results table.
4. If the outcome on v13.x is `pwn`, the next version's design pass
   is written here *with no claim that v13.x improved things*.

The outcome column in the version table is updated as each step
completes. No forecasting in the "Outcome" cells.

## Measurements for v13.3

v13.3 landed with a different scope than the plan table predicted.
The plan had v13.3 doing "chained handler decryption"; the red-team
critique of v13.2 made clear that handler-level chaining addresses
the wrong oracle. What A24 actually exploited was the `compile()`
correctness check on decrypted `_VMC` — the attacker could reject
a wrong password in microseconds without ever executing the VM.
v13.3 therefore targets that specific oracle.

### Changes from v13.2

- **VM runtime inlined as plaintext.** There is no `_VMC`
  encrypted-Python-source blob. The VM lives at module scope in the
  bootstrap, with per-build diversified opcode values and `_DISC`.
  A22-style "the VM source is visible" surveys now report 14 OP_\*
  constants, `def run(`, `_mask(`, etc. as visible — this is
  intentional. The point is that nothing about revealing those names
  lowers the attacker's cost: the password-gated content is what
  scrypt protects, not the opcode table.
- **Two chained ciphertext blobs.** `_PA = prog_a XOR keystream(master, _NA)`
  where `master = scrypt(pw, salt)`. `_PB = prog_b XOR keystream(key_b, _NB)`
  where `key_b = sha256(state_key(state_after_prog_a) ‖ master)`. An
  attacker cannot decrypt `_PB` without first running `prog_a` on the
  correct master key. Mixing `master` into `key_b` ensures two
  different wrong passwords do not collapse to the same `key_b`
  (they still often collapse at state_b; see A26 below).
- **Fixed-length output.** The bootstrap always writes `_OUT_LEN + 1 = 65`
  bytes to stdout. Right-pass: first 31 bytes are `FLAG{...}`,
  remaining bytes are deterministic padding from `state_key(state_b)`.
  Wrong-pass: first bytes are whatever garbage opcodes left in
  `state[16]` (typically empty → full 64-byte padding). Same length
  in both cases. Closes the length oracle.
- **No `compile()` oracle target.** Removing `_VMC` removes the
  single cheap structural oracle on decrypted bytes. A random byte
  stream decrypted from a wrong password does not parse as Python —
  but there is nothing the attacker tries to parse as Python.

### Retest of v13.2-era attacks against v13.3

| Attack | What it did on v13.2 | Outcome on v13.3 |
|--------|----------------------|-------------------|
| A22 static-leakage survey | 0 OP_\*, 0 handler bodies, 2 high-entropy blobs | **Scope changed**: 14 OP_\* now visible by design, two ciphertext blobs present; no encrypted-Python-source blob. Leaks specific to v13.3: `hashlib.scrypt`, `surrogateescape`, `def run(`. The v13.2-era `FLAG{` comment leak was closed. |
| A23 exec-replace          | patched `exec(vm_src); run(prog)` block      | **Mechanically N/A**: no `exec(vm_src)` pattern to patch. The v13.3-native port (`a23_prog_b_dump_v13_3.py`) confirms: right-password prog_a and prog_b decrypt to valid opcode streams starting with the stub's diversified `OP_LDI = 0x66` byte; wrong-password dumps are high-entropy uniform bytes. The dump surface narrows to just the two prog streams. |
| A24 v13.2-native brute    | 43.6 guesses/s, compile() oracle, 0 FP       | **No longer applicable** as-written: `_VMC` is gone. The v13.3 analogue is A25 below. |

### v13.3-native attacks

**A25 — brute-force economics against v13.3**
(`tests/pentest_v13_3/attacks/a25_scrypt_brute_v13_3.py`):

Runs the full attacker-side pipeline per guess: `scrypt` → decrypt
prog_a → run VM → derive key_b → decrypt prog_b → run VM → inspect
output. Uses the stub's own plaintext VM (via `exec` into an
attacker namespace — no reimplementation).

- Throughput on this workstation (single CPU core): **14.2 guesses/s**
  (~70 ms/guess, vs v13.2's ~23 ms/guess).
- Compile oracle: **gone**. The attacker cannot reject a guess
  without running prog_a and prog_b.
- Content oracle: wrong-password outputs begin empty (state[16]=0
  int, so `head = b""`); right-password output begins
  `b'FLAG{v13_3_chained_state_keyed}'`. `out[:5] == b'FLAG{'` is a
  perfect discriminator for an attacker who knows the flag format.
  False-positive check: 0/8 wrong guesses produced a `FLAG{` prefix.
- Extrapolated wall-clock (same GPU figures as A24, halved to
  account for GPU-side VM execution overhead: ~5 kH/s on a 4090):

  | Dictionary   | 1 core   | 16 cores | RTX 4090 (~5 kH/s) | 8× H100 (~50 kH/s) |
  |--------------|----------|----------|---------------------|---------------------|
  | rockyou (14M) | 274.7 h | 17.2 h   | 0.8 h               | 0.1 h               |
  | 1B guesses   | 19624 h | 1227 h   | 55.6 h              | 5.6 h               |
  | 10B guesses  | 196240 h| 12265 h  | 556 h               | 55.6 h              |

Interpretation: v13.3's per-guess cost is ~3× v13.2's, but still
scrypt-dominated. Rockyou on a single GPU still falls in under an
hour. The attacker pays the scrypt cost; the rest is microseconds.
**v13.3's security bound is still password entropy × scrypt cost.**

**A26 — output collapse-class oracle**
(`tests/pentest_v13_3/attacks/a26_collapse_class_oracle.py`):

Measures whether wrong-password outputs cluster into a small number
of byte-equal classes. 40 wrong guesses on a reference build:

- Distinct classes: **16** / 40.
- Largest class fraction: **52.5%** (21/40 wrong guesses share
  output).
- Right-password output: unique class, starts `FLAG{`.
- Verdict: **SEVERE**. The fixed-length-output framing of v13.3
  closed the length oracle but not the value oracle.

Root cause: garbage prog_a and prog_b decrypted from wrong
passwords rarely contain any of 16 valid opcode bytes (≈6% of byte
values). Under the total-dispatch VM, most bytes become NOP, and
state_a and state_b converge to fixed-point attractors near the
all-zero initial state. Many wrong guesses produce
`state[16] = 0`, `state_key(state_b) = sha256(zeros)`, and hence
identical 64-byte padding output.

This does not break v13.3 below the A25 bound — the attacker still
pays scrypt per guess — but it narrows the shortlist the content
oracle has to verify. In practice, A25 already lets the attacker
discriminate in one memcmp; A26's filtering contribution is modest.
It is recorded here because the v13.3 bootstrap comments claimed to
"close the output-length oracle" and one should not also claim to
have closed the value oracle. The claim as shipped is precisely:
fixed length, non-fixed value, modal collapse.

### v13.3.1 and v13.3.2 — making the chain load-bearing

A parallel audit + pentest pass on v13.3 produced A27, A28, A29. A27
was the interesting one: the chain construction (`_PB` keyed by
`state_key(state_after_prog_a)`) was sold as forcing a per-guess
`prog_a` execution, but v13.3's `prog_a` was a seed-installer with a
public `SEEDS` constant in the pyguard source. An attacker
precomputed `state_key` once from open-source constants and skipped
`prog_a` on every guess. The chain added zero cryptographic work.

**v13.3.1** (committed):

- `prog_a` is no longer a seed-install no-op. It performs
  `OP_SCRYPT [20, 30, 31]` — a second scrypt on master-derived
  inputs injected into state[30]/state[31] via a new
  `run(..., init_slots=)` parameter. `state_key(state_a)` then
  length-frames slot 20 = scrypt(pw_in, salt_in) into its digest, so
  it cannot be precomputed.
- Bonus fixes: `state_key` gets length-framed concatenation (closes
  a v13.3 hygiene bug where `state[16]=b"AB"` + `state[17]=b"CD"`
  hashed identically to `state[16]=b"ABCD"` + `state[17]=b""`). The
  output path always traverses the padding branch (F3). Dead
  `run_chained` helper removed (F7).
- Measured outcome (A27 vs v13.3.1): SEEDS-based `state_key`
  precompute produces 0/4 `FLAG{` hits — the A27 attack is dead.
- Measured outcome (A30 vs v13.3.1): a smart attacker who caps
  `max_steps` to 200 pays only **1.46× single-scrypt** per wrong
  guess — not the 2× the design claimed. Reason: on a wrong
  password, `prog_a` decrypts to 5 garbage bytes, and OP_SCRYPT only
  fires when a masked byte happens to land on the OP_SCRYPT value
  (~2% probability per byte). 98% of wrong guesses skipped the
  inner scrypt entirely. The chain was load-bearing only on the
  right-password path; dictionary cost stayed at ~1× scrypt.

**v13.3.2** (committed, current tip):

- Inner scrypt is computed in the *bootstrap*, unconditionally, not
  inside the VM. `prog_a` becomes HLT-only (1-byte plaintext). The
  bootstrap does:
  ```
  pw_in   = sha256(m + b"v13_3_2_pa_pw")[:16]
  salt_in = sha256(m + b"v13_3_2_pa_salt")[:16]
  inner   = scrypt(pw_in, salt=salt_in, n=_N, r=_R, p=_P, dklen=_DK)
  state_a = run(prog_a, init_slots={20: inner})
  ```
  Every guess pays both scrypts. The attacker cannot skip — any
  substitute for `inner` yields a wrong `state_key`, wrong `kb`,
  garbage `prog_b` decrypt, and no `FLAG{` oracle signal.
- Measured outcome (A31 vs v13.3.2):
  - Aligned attacker throughput: **23.6 guesses/s** on this
    workstation.
  - Single-scrypt baseline: 51.8 guesses/s.
  - Aligned / single-scrypt ratio: **2.20×** (target ≈ 2×, met).
  - Aligned / two-scrypt baseline: 1.11× (the 11% overhead is VM
    + XOR + sha256 framing, not a leak).
  - Skip-inner attacks (state[20] = `b""`, `b"\x00"*64`, random
    64 bytes): 0 `FLAG{` hits on right password — deterministic
    fail.

| Attack | v13.3 | v13.3.1 | v13.3.2 | v13.3.3 |
|--------|-------|---------|---------|---------|
| A25 brute-force (guesses/s) | 14.2 | n/a (replaced) | — | — |
| A27 precompute skip prog_a | works | dead | dead | dead |
| A30 honest 2× multiplier | n/a | **1.46×** | n/a (superseded) | n/a |
| A31 skip-inner + throughput | n/a | n/a | **2.20× single, 0 skip hits** | **2.38×** |
| A26 modal class fraction | 52.5% | ~50% | 40.0% | measured per build |
| A28 FLAG-in-frame-locals | yes | yes | yes | yes |
| A32 printable-head oracle | n/a | n/a | fires | fires |
| A33 self-consistency oracle | n/a | n/a | **fires (INFINITE selectivity)** | **fires (structural)** |
| A34 scope arbitrary-exec probe | n/a | n/a | EXECUTES eval | **blocked (empty scope)** |

The A30/A31 iteration is a concrete illustration of
MEMORY.md's "write a new attack after each hardening round":
v13.3.1 looked like a clean fix for A27 until A30 quantified it,
at which point the 2× claim collapsed. v13.3.2 is the actual
2×-per-guess chain.

### v13.3.3 — defense-in-depth + F5 scope narrowing

**v13.3.3** (committed). Four in-family hygiene fixes identified
by audit after v13.3.2; A33 (self-consistency oracle, found by
pentest against v13.3.2) remains structural and motivates the v14
departure from the password-gate family.

- **F5 — VM scope = `{}` instead of `dict(builtins.__dict__)`.**
  Both `prog_a` (HLT-only) and `prog_b` (LDI/LDB/XAB/HLT only)
  never use `OP_RES`/`OP_CL0`/`OP_CL1` on the right-pass, so an
  empty scope is functionally equivalent for correct execution.
  It changes *wrong-pass* behavior: a crafted password whose
  garbage `prog_b` happens to dispatch `OP_RES("eval") + OP_CL1`
  with attacker-controlled bytes in the argument slot could
  previously pipe strings through `eval()`. A34 demonstrates the
  differential directly: same crafted `prog_b` runs under both
  scopes, prints `PWNED-SCOPE-EXPOSED` under v13.3.2 scope,
  prints nothing under v13.3.3 scope.
- **F2 — state_key type tag.** Previously `int=0`, `None`, and
  `bytes=b"\x00"` all serialized to the same byte sequence in
  `state_key`, so three distinct state shapes produced the same
  `key_b`. Now a type byte (0x01 int, 0x02 bytes, 0x03 other)
  domain-separates them. Also adds a version domain tag
  `v13_3_3_state_key` so `state_key` is not cross-version
  identical. Changes right-pass `key_b` (new cryptographic
  derivation, not an attack break by itself); eliminates the
  aliasing.
- **F3 — `_DISC` rejection sampling.** v13.3.2's diversify used
  `if disc == 0: disc = 1`, which gave `disc == 1` probability
  2/256 and every other nonzero value 1/256. Replaced with
  rejection sampling (rehash with counter until nonzero), so each
  of 1..255 occurs with equal probability 1/255.
- **F4 — salt-mixed inner-scrypt derivation.** `pw_in`/`salt_in`
  now mix the public build salt and use new tag strings
  (`v13_3_3_pa_pw` / `v13_3_3_pa_salt`). Before, two stubs
  sharing an outer password also shared `inner = scrypt(f(m),
  g(m))` as a deterministic function of `m` only — an attacker
  who broke one build could reuse the `pw_in → inner` map
  against another build. Build-specific `inner` closes that
  cross-build rainbow-table path. Per-guess cost unchanged.

None of F2–F5 changes the asymptotic attacker cost. They close
narrow channels that were non-load-bearing in v13.3.2's measured
security but that the audit flagged as "wider attack surface than
needed." The structural ceiling remains **A33**: the right-pass
pad is a pure function of the head, so an attacker who can produce
any candidate output can verify self-consistency with one sha256,
no FLAG-literal knowledge required. No in-family fix exists — the
defender cannot mix master into the pad without also letting the
attacker (who has the same master on their guess) do the same
prediction. v14 must leave the password-gate family.

### What v13.3.2 still does *not* fix

- **Content oracle** (`out[:5] == b"FLAG{"`): structural. Any
  password-gated emitter exposes this. v14 target.
- **Self-consistency oracle (A33)**: strictly more dangerous than
  the FLAG{ content oracle. The right-pass `state_b` is
  deterministic in the output head (SEEDS + bytearray(head) +
  zero), so `out[len(FLAG):]` is a pure function of `out[:len(
  FLAG)]` via `state_key`. An attacker scans head-lengths in
  [4, 63), verifies `out[head_len:] == state_key([SEEDS,
  bytearray(head), 0, ...])[:OUT_LEN - head_len]` with one
  sha256, and flags the right-pass output with zero false
  positives across every N we've measured. No FLAG-prefix
  knowledge required, no reference outputs required. In-family
  fix does not exist: anything mixed into the pad that the
  defender can compute, the attacker can also compute (they
  have the same master on their guess). v14 target.
- **Memory residue** (A28): tracer + frame-local inspection
  recovers the FLAG from 278 frame samples across a single right-
  password run. The flag must materialise in memory to be printed;
  no in-family fix exists. v14 target.
- **Value-class collapse** (A26): ~40% modal class on v13.3.2.
  Moderate — reduces the shortlist the content oracle verifies but
  doesn't reveal the flag on its own.
- **Per-guess cost remains scrypt-bounded.** Doubling scrypt moves
  rockyou-on-a-4090 from ~45 min to ~90 min. Not an asymptotic
  improvement; not a categorical one.

### What v13.3 does *not* fix

- **Per-guess cost is the same order as v13.2.** Scrypt dominates
  both. v13.3's 3× slowdown against A25 vs A24 is real but does
  not move the bar below "GPU-cracks-rockyou-in-an-hour."
- **Content oracle on output bytes.** Anyone who knows a flag
  starts `FLAG{` can discriminate right from wrong in one memcmp.
  This is a structural property of every scheme where the output
  is the flag on correct input. No in-family patch to v13.\*
  addresses it; v14 must leave the password-gate family.
- **Handler names are back in plaintext.** v13.3 accepted this
  trade-off to kill the compile() oracle. An analyst reading the
  stub sees the full VM definition, including `hashlib.scrypt`
  and the keystream structure. None of this reveals the flag, but
  none of it imposes analyst cost either.
- **The VM runtime is small (~200 LOC).** A motivated analyst can
  read and internalise it in under an hour. Once understood, the
  per-build diversification only renames opcodes; the VM's shape
  is fully known.
- **v13.3 is scrypt + a very small program emitter.** The
  obfuscator's contribution to security is the scrypt parameters
  and nothing else. That is the same conclusion as v13.2.

## Where the v13 family hits its ceiling

After three rounds (v13.1 → v13.2 → v13.3) the pattern is clear.
Every round has closed a specific oracle:

- v13.1 → v13.2: closed static-structure oracle (A17/A21 had no
  `_PAYLOAD` or `OP_*` to anchor on).
- v13.2 → v13.3: closed compile() oracle (no `_VMC` to parse as
  Python).
- v13.3 → ??.??: would next close the value-class oracle (A26),
  e.g. by ensuring every wrong password produces unique output
  bytes.

But **every one of these rounds leaves the content oracle in
place.** An attacker with ground-truth knowledge of the flag format
discriminates right-pass from wrong-pass in one memcmp per guess.
The value-class oracle is a mild amplifier of that; closing it
does not move the bound.

The structural reason: any password-gated scheme where the output
is the flag-on-correct and something-else-on-wrong exposes the
flag format as its own oracle. The attacker's cost is always
scrypt × dictionary size, with `FLAG{`-prefix as the pass/fail
check. No amount of handler-chaining, opcode-permuting, or
output-padding within this design space changes that.

**v13 is therefore not an obfuscator. It is encrypted payload
delivery with a per-build-diversified Python bootstrap.** The only
parameter that affects attacker cost is the scrypt work factor.
The obfuscation machinery contributes ~hours of one-time analyst
cost to understand the VM, amortised across every build ever
shipped. That is a speed bump, not a defence.

## v14 direction: leave the password gate

v14 will not be v13.4. The granular plan table above (v13.4–v13.10)
assumed incremental hardening inside the password-gate family. The
measurements of v13.3 show that family has no remaining room.

v14's design constraint is: **the obfuscator must make
*understanding the program* expensive, independent of whether any
password is used.** A working definition:

> An analyst, given the stub and unlimited compute but no prior
> knowledge of the specific build, must spend ≥ N human-hours to
> emit an equivalent program in Python (or any language). N is
> set by the challenge author; a CTF-grade target is N ≥ 8. N
> must grow at least linearly with per-build randomness, so that
> two analysts cannot split the work across builds.

Candidate v14 techniques, each of which must *pass its own attack*
before being claimed done:

1. **Mixed Boolean-arithmetic (MBA) obfuscation of the core
   semantics.** Flag assembly doesn't happen as `state[i] ^= b`;
   it happens inside a polynomial identity that equals the XOR
   only at specific state configurations. Attack: symbolic
   simplification via Z3/angr.
2. **Opaque predicates driving dispatch.** Instead of a switch on
   `op`, dispatch via a predicate known only at runtime (e.g., a
   multi-variate polynomial that evaluates to the opcode index
   modulo N). Attack: branch-tracing + predicate synthesis.
3. **Protocol-based output.** The stub does not emit the flag; it
   emits a transcript of interactions with an outside verifier
   (a server, a TPM, a local file that the challenge ships). The
   flag is the verifier's response to a correct transcript.
   Attack: replay / offline simulation of the verifier.
4. **Polymorphic self-modification.** The VM rewrites parts of
   itself mid-execution. The bytes visible at module load time
   do not include the handlers that actually emit the flag.
   Attack: dynamic trace + delta-decoding.

None of these remove the process-level debugger threat; none
claim to. They target the specific v13-family weakness: that the
only expensive thing in v13 is password guessing, which is
dictated by the user's password choice, not by the obfuscator.

## Current backlog, in priority order

1. ~~Write v13.2: per-build opcode permutation + A22 adaptive
   classifier. Measure.~~ **Done.** See "Measurements for v13.2".
2. ~~Write v13.3: close compile() oracle, chained encryption,
   fixed-length output. Measure.~~ **Done.** See "Measurements
   for v13.3". Outcome: compile() oracle closed; content oracle
   remains; partial value-class collapse (A26).
3. ~~v13.3.1/.2/.3 hardening rounds.~~ **Done.** v13.3.1 closed
   A27's SEEDS-precompute but left a measurable skip-inner shortcut
   (A30, 1.46×). v13.3.2 moved inner scrypt into the bootstrap for
   a real 2.20× per-guess multiplier (A31); A32/A33 followed as
   pentest against v13.3.2. v13.3.3 applied four in-family
   fixes (F2–F5) and introduced A34 as the per-round new attack;
   A33 remains the uncloseable ceiling and forces v14.
4. **Decide v14 direction** before writing any code. The options
   above (MBA, opaque-predicate dispatch, protocol-based output,
   polymorphic self-modification) are not mutually exclusive and
   each needs its own attack specification up front. Red-team
   rule: **the attack spec exists before the implementation
   starts.** The attack spec for v14 is A33 — whatever v14 does,
   it must make `out[len(FLAG):]` not a pure function of
   `out[:len(FLAG)]` computable from public constants alone.
5. Prototype the chosen v14 technique on a minimal example (not
   integrated with the v13 bootstrap). Measure attacker cost on
   the minimal example before promoting to a full build.

The red-team rule stands: write the attack after the hardening
round, never declare unbreakable, and stop writing prose that calls
progress "good."
