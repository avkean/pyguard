# PyGuard v6 Hardening Plan

## Status: In Progress

## Context
The v5 obfuscator was one-shotted by an LLM that:
1. Followed the linear decrypt chain (Stage 1 → 2 → interpreter → IR)
2. Copied the SPN cipher and ran it offline
3. Ignored anti-analysis (only execution-gating, not cryptographic)
4. Extracted the interpreter (single zlib+base64 blob)
5. Mapped IR nodes 1:1 back to Python (tree structure mirrors AST)

## Architecture Changes (v6)

### Completed
- **AST-level transforms** (`lib/v5/transform_ast.py`): Applied BEFORE IR compilation
  - Control flow flattening: if/while/for → state machine dispatcher with random state values
  - Expression decomposition: nested calls/binops → temporary variable chains
  - Opaque predicates: always-true conditions (Fermat, n^2>=0) guarding dead code
  - Constant unfolding: integers → arithmetic expressions (XOR, shift, add)
  - MBA obfuscation: x+y → (x^y)+2*(x&y), etc.
  - String obfuscation: literals → bytes([...]).decode('utf-8') with XOR key
- **Integrated into build_ir.py**: `compile_to_ir()` now calls `transform_ast_tree()` before lifting

### In Progress (delegated to subagents)
- **Rolling IR binary encryption**: XOR each byte with LCG-derived rolling key; noise byte injection at positions from schema
- **Interpreter self-obfuscation**: Build-time AST transform of runtime_interp.py — rename all identifiers, encode string literals, add dead code, scramble method order

### Pending
- **Fragmented interpreter loading**: Split interpreter into N encrypted chunks; chunk N's key = hash(chunk N-1's plaintext)
- **Anti-analysis hardening**: Timing checks, cryptographic binding (debug detection poisons rolling key, not just exit), stack depth monitoring
- **TypeScript pipeline updates**: schema.ts (binKey, noiseSchedule), assemble.ts (set _PG_BIN_KEY), gen-v5-stub.mjs
- **Full test suite validation**: All 15 test cases
- **Adversarial self-audit**: Try to crack own output, iterate

## Key Files
- `lib/v5/transform_ast.py` — NEW: AST-level obfuscation transforms
- `lib/v5/build_ir.py` — MODIFIED: calls transform_ast_tree before lifting
- `lib/v5/runtime_interp.py` — TO MODIFY: rolling XOR in _pg_parse_bin
- `lib/v5/schema.ts` — TO MODIFY: add binKey, noiseSchedule
- `lib/v5/assemble.ts` — TO MODIFY: set _PG_BIN_KEY, fragment loading
- `lib/obfuscate.ts` — TO MODIFY: anti-analysis improvements
- `scripts/obfuscate_runtime.py` — NEW: build-time interpreter obfuscator
- `scripts/gen-interpreter-src.mjs` — TO MODIFY: run obfuscator before compress

## Design Principles
1. Eliminate clean layer boundaries — make layers interdependent
2. Maximize state tracking burden — many interacting variables
3. Maximize simulation requirement — can't shortcut, must simulate
4. Maximize noise — real and fake code mixed together
5. Break 1:1 IR-to-Python mapping — CFF + expression splitting + opaque predicates
