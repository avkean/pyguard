# PyGuard

Python source code obfuscator. Transforms source into a protected stub that runs identically but resists casual reverse-engineering.

**Website:** [pyguard.avkean.com](https://pyguard.avkean.com)

## How it works

PyGuard v5 never compiles user source at runtime. Instead it:

1. **Compiles to IR** -- Python AST is lowered into an instruction-tape IR (Code nodes with I-prefixed opcodes like `IAssign`, `IFor`, `ITry`, `IFunctionDef`), not a statement tree.
2. **Randomizes the schema** -- every stub gets a unique per-build schema that remaps all field names, op tags, and field orderings to random tokens. String literals are XOR-masked. Nothing in the shipped blob has stable labels.
3. **Packs to binary** -- the IR is serialized into a custom binary format (not JSON), then zlib-compressed.
4. **Encrypts in layers** -- the packed IR and schema are independently encrypted with derived keys (KDF + XOR pepper + AES-CTR). The schema is only reconstructed after the interpreter loads.
5. **Embeds an interpreter** -- a generic AST-walking interpreter (`runtime_interp.py`) is deflate-compressed and embedded as a base64 blob. It parses the binary IR into opaque `_PGMap` wrappers and positional tuples, never plain dicts/lists.
6. **Wraps in a 3-stage launcher**:
   - **Stage 0**: integrity checks (code-object digest, file hash, recompilation detection)
   - **Stage 1**: anti-trace (clears `settrace`/`setprofile`, walks `f_trace` pointers via traceback frames, checks `gettrace`/`getprofile`), decrypts stage 2
   - **Stage 2**: decrypts schema, sets up runtime layout tables, decrypts + decompresses IR, calls `run_blob()`

The interpreter resolves every field through the per-build layout map at runtime. A captured payload yields masked strings, randomized field names, randomized tag values, and randomized field positions -- not a readable AST.

## Anti-tampering

- Code-object deep digest (`co_code` tree hash) detects bytecode patching
- File-on-disk recompilation check catches save-and-re-run attacks
- `sys.settrace(None)` + `sys.setprofile(None)` before sensitive paths
- Traceback-based `f_trace` frame walker catches tracers that spoof `gettrace()`
- `compile` builtin identity check
- No plaintext hook points (`_PG_KEYS`, `_PG_TAGS`, `run_blob` etc. are constructed indirectly)

## Attack scoreboard

All attacks are in `tests/pentest/`. Run with `bash tests/pentest/run_scoreboard.sh`.

| # | Attack | v4 | v5.0 | v5.1 | v5.2 | v5.3 |
|---|--------|----|----|------|------|------|
| 4 | Static AST/string scan | HELD | HELD | HELD | HELD | HELD |
| 5 | LLM deobfuscation | HELD | HELD | HELD | HELD | HELD |
| 6 | AST surgery on stub | HELD | HELD | HELD | HELD | HELD |
| 7 | Expression walker | HELD | HELD | HELD | HELD | HELD |
| 8 | PEP 578 audit hook on `compile` | **PWNED** | HELD | HELD | HELD | HELD |
| 9 | `settrace` source dumper | **PWNED** | HELD | HELD | HELD | HELD |
| 11 | `json.loads` monkey-patch | n/a | **PWNED** | HELD | HELD | HELD |
| 12 | `settrace` + key-based frame scan | n/a | **PWNED** | **PWNED** | HELD | HELD |
| 13 | `settrace` + structural shape scan | n/a | **PWNED** | **PWNED** | **PWNED** | HELD |
| 14 | Trace sabotage (spoof settrace/gettrace) | n/a | n/a | n/a | n/a | HELD |
| 15 | Compile hook surgery | n/a | n/a | n/a | n/a | HELD |

### Honest limits

PyGuard is an obfuscator, not an encryptor. The stub must eventually hand data to CPython to execute, so a sufficiently motivated attacker with full runtime access can always recover it. The question is cost, not possibility. If you need cryptographic guarantees, use native compilation, a server-side API, or a hardware enclave.

After every hardening round we write a new attack. If every row says HELD, the next attack hasn't been written yet.

## Stub size

| Version | Approach | Typical stub | Cold exec |
|---------|----------|-------------|-----------|
| v5.0 | Plaintext interpreter inlined | ~1470 lines | ~320 ms |
| v5.1 | Plaintext interpreter inlined | ~13500 lines | ~320 ms |
| v5.2+ | Compressed interpreter + binary IR | ~285 lines | ~60 ms |

Cold exec is `time python3 stub.py` on `01_print.py`; dominated by Python startup.

## Local setup

```bash
git clone https://github.com/yourusername/pyguard.git
cd pyguard
npm install
npm run dev
```

Generate a v5 stub locally:
```bash
node --import tsx scripts/gen-v5-stub.mjs <source.py> -o out.py
```

Run tests:
```bash
npx tsx tests/run_tests.ts
bash tests/pentest/run_scoreboard.sh
```

## License

Copyright 2025 avkean. Licensed under [GPL-3.0](LICENSE).
