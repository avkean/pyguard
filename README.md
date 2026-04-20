# PyGuard

PyGuard is a Python source obfuscator that turns a Python program into a protected pure-Python stub.

PyGuard v5 is a friction system, not confidential execution. The goal is to make reverse-engineering and reusable automation meaningfully harder, especially after one clean run, while staying honest that an attacker-controlled Python process cannot offer strong secrecy guarantees.

Website: [pyguard.avkean.com](https://pyguard.avkean.com)

## What v5 Does

At a high level, v5:

1. rewrites source into a structurally alien form
2. lowers it into custom IR
3. randomizes the schema per build
4. packs the IR into a custom binary format
5. encrypts the payload in multiple stages
6. runs it through an embedded marshaled interpreter

It does not ship plaintext stage source and it does not rely on runtime `compile()` of decrypted user code.

## Current Hardening Strategy

The main failure mode for Python obfuscation is not just "source text recovered." It is "the decisive logic or decisive data still survives somewhere as one attacker-useful representation."

PyGuard's current v5 direction is therefore:

- keep the wrapper hard enough to avoid trivial one-run extraction
- permanently deform source before IR lowering
- move decisive secret-centric closures into per-build bespoke semantics where the payoff justifies the cost
- avoid single-stage choke points, so recovering one artefact or one runtime view is not enough to extract, force, or generalize

In practice, that means password checks, win gates, reward emission, and similar secret-bearing closures should not survive as obvious compare/jump/call structure inside generic IR when they can be lifted into semantic islands.

## Core v5 Pieces

- `lib/v5/transform_ast.py`
  Build-time AST transforms. This is where source deformation lives.

- `lib/v5/build_ir.py`
  Lowers transformed AST into v5 IR and tagged marshal payloads.

- `lib/v5/runtime_interp.py`
  The runtime interpreter for v5 IR and semantic-island payloads.

- `lib/v5/schema.ts`
  Per-build schema/tag/layout definitions used by the binary layer.

- `lib/obfuscate.ts`
  Packs, encrypts, and assembles the final stub.

- `scripts/gen-v5-stub.mjs`
  Main local entry point for generating a v5 stub.

## Permanent Source Transforms

These transforms survive full payload recovery because they change the program before IR packing:

- identifier renaming
- attribute mangling
- import concealment
- local slot lifting
- function body fusion
- opaque predicates
- control-flow flattening
- constant deformation
- semantic islands for secret-bearing regions

The newest important addition is semantic islands:

- transformed AST emits `__pyguard_semantic_island__(payload)`
- IR lowers this to `IIsland`
- runtime executes the payload through a bespoke per-island VM
- the current payload format is `PGSI2`, with per-island variation in opcode space, operand encoding, layout, stack/call convention, and dispatch shape
- string and bytes material can be fragmented in the payload and materialized late inside the island runtime
- decisive island constants no longer live entirely inside `PGSI2`; per-island auxiliary key material is transported separately in the encrypted manifest
- a recovered island payload by itself should therefore not be enough to read the real decisive literals for the protected region

This targets the real root issue: preventing a protected secret check or reward path from collapsing into a tiny clean equivalent.

## Release Gates

Use these in order:

```bash
npx tsx tests/run_disclosure_checks.ts
npx tsx tests/run_tests.ts
bash tests/pentest/run_scoreboard.sh
```

What they mean:

- `run_disclosure_checks.ts`: primary release gate, including the real `tests/test_rev/dist.py` closure-lift assertion and a guard against plain decisive literals surviving in the lifted island payload
- `run_tests.ts`: compatibility regression gate
- `run_scoreboard.sh`: attack dashboard

The scoreboard matters, but it is not the product definition. If the shortest one-run recovery path still works, the hardening round is not done even if many attacks say `HELD`.

## Honest Limits

PyGuard is deliberately honest about what it cannot guarantee:

- An attacker who can run the program controls the Python process.
- A sufficiently complete symbolic/static emulator can recover what the runtime recovers.
- Runtime values are not protected. If the program prints a secret, running the program reveals it.
- Import names still have unavoidable leakage through Python's import system.
- Artifacts are CPython-minor-specific and should fail closed on mismatches.

If you need cryptographic secrecy, move the secret off the client.

## Local Use

Install:

```bash
npm install
```

Generate a stub:

```bash
node --import tsx scripts/gen-v5-stub.mjs input.py -o out.py
```

Regenerate embedded Python sources after editing `lib/v5/build_ir.py` or `lib/v5/runtime_interp.py`:

```bash
npm run gen:v5
```

## Red-Team Fixture

The main local semantic-hardening fixture is:

- clean source target: `tests/test_rev/dist.py`
- already-obfuscated sample: `tests/test_rev/sillybillysgame.py`

When validating semantic-island work, use `dist.py` as the source target. The important question is whether the clean secret-bearing logic still collapses into a short equivalent after protection.

For this fixture class, a green result means more than "the wrapper held" or "the island exists." A recovered `PGSI2` blob alone should not reveal the flag, the reward text, or enough decisive truth to stop at that layer.

## License

Copyright 2026 avkean. Licensed under [GPL-3.0](LICENSE).
