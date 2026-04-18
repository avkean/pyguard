# PyGuard

Python source code obfuscator. Transforms source into a protected stub that runs identically but resists casual reverse-engineering.

**Website:** [pyguard.avkean.com](https://pyguard.avkean.com)

## How it works

PyGuard never compiles user source at runtime. Instead it:

1. **Compiles to IR** -- Python AST is lowered into an instruction-tape IR (Code nodes with I-prefixed opcodes like `IAssign`, `IFor`, `ITry`, `IFunctionDef`), not a statement tree.
2. **Randomizes the schema** -- every stub gets a unique per-build schema that remaps all field names, op tags, and field orderings to random tokens. String literals are XOR-masked. Nothing in the shipped blob has stable labels.
3. **Packs to binary** -- the IR is serialized into a custom binary format (not JSON), then zlib-compressed.
4. **Encrypts in layers** -- the packed IR and schema are independently encrypted with derived keys (KDF + XOR pepper + AES-CTR). The schema is only reconstructed after the interpreter loads.
5. **Embeds an interpreter** -- a generic AST-walking interpreter (`runtime_interp.py`) is deflate-compressed and shipped as marshaled bytecode (no `compile()` audit event fires at runtime). It parses the binary IR into opaque `_PGMap` wrappers and positional tuples, never plain dicts/lists.
6. **Wraps in a 3-stage launcher**:
   - **Stage 0**: integrity checks (code-object digest, file hash, recompilation detection) and env-witness probing
   - **Stage 1**: anti-trace (clears `settrace`/`setprofile`, walks `f_trace` pointers via traceback frames, checks `gettrace`/`getprofile`), decrypts stage 2
   - **Stage 2**: decrypts schema inside the interpreter's own boot frame, sets up runtime layout tables, decrypts + decompresses IR, invokes `run_blob`

The interpreter resolves every field through the per-build layout map at runtime. A captured payload yields masked strings, randomized field names, randomized tag values, and randomized field positions -- not a readable AST.

## Env-integrity binding

Every stub folds a set of environmental witness bytes into its master seed. In a clean env each witness hashes to the build-precomputed value; any attacker probe flips a bit, the derived key diverges, and decryption silently produces garbage bytes that fail zlib / marshal. There is no visible anti-debug branch to NOP out.

Witnesses currently covered:

- **Code-object canonical hash** -- bytecode patching between the markers inside the stub changes the hash.
- **Captured-builtin type identity** -- `type(marshal.loads) is type(zlib.decompress)` etc.; any Python-level wrapper flips `'builtin_function_or_method'` to `'function'`.
- **Settrace / setprofile / gettrace / getprofile** -- active tracers or Python-level replacements.
- **`sys.monitoring` (PEP 669)** -- tool_ids 0..5; any pre-reserved slot.
- **`gc.callbacks` / `gc.get_debug()` / `tracemalloc.is_tracing()`** -- GC-boundary trace surfaces.
- **Signal / faulthandler / itimer** -- `SIGPROF` handler, `ITIMER_{PROF,VIRTUAL,REAL}` armed, `faulthandler.is_enabled()`.
- **Unaudited signals** -- `SIGUSR1`, `SIGUSR2`, `SIGXCPU`, `SIGXFSZ` handler installed (uses `callable()` check because `SIGXFSZ` defaults to `SIG_IGN`, not `SIG_DFL`, on POSIX).
- **Exception hooks** -- `sys.excepthook`, `sys.unraisablehook` replaced.

## Permanent source transforms

These make the original source literally unrecoverable byte-for-byte even if an attacker fully recovers the decrypted IR:

- **Identifier renaming** (vars, functions, methods) with per-build randomization.
- **Attribute mangling** -- `obj.foo` becomes `_gA(obj, _ATAB[idx])` with an encrypted attribute name table.
- **Import concealment** -- `from collections import Counter` routed through an encrypted import table.
- **Local slot lifting** -- function locals and parameters rewritten to `_s[N]` subscripts so variable names leave the string pool entirely.
- **Function body fusion** -- eligible top-level defs dissolve into a module-level `_pg_F(fid, args)` mega-dispatcher keyed by opaque 32-bit fids; function boundaries are gone at source.
- **Constant unfolding + MBA rewriting** on numeric literals in user code.
- **CFG flattening** and **opaque predicates** on control flow.

## Attack scoreboard

All attacks live in `tests/pentest/`. Run with `bash tests/pentest/run_scoreboard.sh`.

Current status against 15 compatibility stubs with 27 attacks × 15 stubs = 405 cells:

- **390 HELD**
- **15 CRASH(124)** — c9 gc-walk attack trips the 30 s scoreboard timeout on every stub (perf wall + seed divergence; dual HELD, not a regression).
- **0 PWNED**

`a37_import_hook` still PWNs `18_import_leak.py` (import-concealment canary) because Python's own module init leaks `fromlist` entries like `OrderedDict`. This is an accepted honest limit — documented below, not a scoreboard regression.

## Honest limits

PyGuard is an obfuscator, not an encryptor. The stub must eventually hand data to CPython to execute, so:

- A fully symbolic emulator of the decryptor chain recovers the same bytes the runtime does — in a clean env the witnesses all evaluate to known constants and the canonical hash is computable statically. The defense is that the chain is large, multi-stage, and schema-randomized per build, raising the cost of emulation.
- `from X import Y` leaks `Y` through Python's import system regardless of concealment; the import-concealment defense reduces the surface but cannot eliminate it.
- Runtime VALUES (e.g. what the program prints) are never protected — capturing stdout is equivalent to running the program.
- If you need cryptographic guarantees, use native compilation, a server-side API, or a hardware enclave.

After every hardening round we write a new attack. If every row says HELD, the next attack has not been written yet.

## Local setup

```bash
git clone https://github.com/avkean/pyguard.git
cd pyguard
npm install
npm run dev
```

Generate a protected stub locally:
```bash
node --import tsx scripts/gen-v5-stub.mjs <source.py> -o out.py
```

Run tests:
```bash
npx tsx tests/run_tests.ts                  # compat suite
bash tests/pentest/run_scoreboard.sh        # attack scoreboard
```

## License

Copyright 2026 avkean. Licensed under [GPL-3.0](LICENSE).
