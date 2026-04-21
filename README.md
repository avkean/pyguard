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
6. runs it through an embedded, LZMA-compressed interpreter source

It does not ship plaintext stage source, it does not rely on runtime `compile()` of decrypted user code, and it no longer exposes a `marshal.loads` execution boundary for stage0/stage1/stage2 or the interpreter itself — those are all compressed source blobs decrypted and exec'd at runtime.

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
- runtime executes the payload through a bespoke, resumable per-island machine
- the current payload format is `PGSI2`, with per-island variation in opcode space, operand encoding, layout, stack/call convention, and dispatch shape
- string and bytes material can be fragmented in the payload and materialized late inside the island runtime
- per-island key material is derived locally at boot from a schema-bound build secret — it is not transported as a separate manifest aux entry
- island-owned name/slot state is sealed: an external write to a protected local is detected on the next read and aborts the island
- the resumable machine does not keep decoded decisive names/consts/handlers/island keys in live, callback-visible frame locals; host-call resume is transcript-bound and rejects tampered state instead of forcing reward
- a recovered island payload by itself is therefore not enough to read the decisive literals, and a local frame write at a host-call boundary can no longer flip the island cleanly to success

This targets the real root issue: preventing a protected secret check or reward path from collapsing into a tiny clean equivalent, and removing the single-stage choke points (one marshal dump, one frame walk, one local write) that make short-path attacks cheap.

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
- `match` (PEP 634) and `except*` (PEP 654) are not yet lowered by the v5 lifter; inputs that use them fail loud at build time with `NotImplementedError` rather than producing a broken stub.

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

## Running the Web Service

The `/api/obfuscate` Next.js route shells out to Python on untrusted input, so the deploy image is hardened along a few axes.

Container:

- `Dockerfile` runs the Node process as an unprivileged `pyguard` user (uid 10001), not root.
- The runtime stage ships CPython 3.9 – 3.14 side-by-side on `$PATH`; the route's `discoverPythons()` probes these on first request.
- `HEALTHCHECK` fetches `/` and expects a 2xx so orchestrators can rotate unhealthy replicas.

Subprocess safety:

- Every `spawnSync` (build_ir, lzma compressor, version probe) has an explicit wall-clock `timeout` with `SIGKILL` on expiry. A hung Python subprocess will not starve the route's 60 s budget or block a worker indefinitely.
- Subprocesses get a minimal whitelisted env (`PATH`, `LANG`, `LC_ALL`, `PYGUARD_V5_SCHEMA`) — not the full Node `process.env`, so Node-side secrets do not leak into the Python build step.
- A 1 MB input cap is enforced before the AST is even parsed.

Rate limiting:

- A per-IP sliding-window limiter (default 10 requests per 60 s, see `lib/rateLimit.ts`) sits in front of the handler. Tune with `PYGUARD_RL_CAPACITY` and `PYGUARD_RL_WINDOW_MS`.
- Responses carry `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and a `Retry-After` header on 429.

Deploy-time env vars:

| Variable | Default | Purpose |
| -- | -- | -- |
| `TRUSTED_PROXY` | `0` | Set to `1` when running behind a reverse proxy; the rate limiter then keys on `x-forwarded-for` / `x-real-ip`. |
| `PYGUARD_PYTHON_BINS` | *(empty)* | Colon-separated list of Python binaries to use instead of probing `$PATH`. |
| `PYGUARD_RL_CAPACITY` | `10` | Max requests per window per IP. |
| `PYGUARD_RL_WINDOW_MS` | `60000` | Rate-limit window length (ms). |
| `PYGUARD_ALLOW_UNOBFUSCATED_IR` | *(unset)* | Opt-in escape hatch for embedded/Pyodide contexts where `transform_ast` genuinely cannot be loaded. Any production deployment should leave this unset — otherwise a broken import silently ships un-deformed IR. |

Obfuscation-quality invariants enforced at build time:

- `randomBytes` in `lib/obfuscate.ts` throws if `crypto.getRandomValues` is missing rather than degrading to `Math.random()`.
- `compile_to_ir` raises when `transform_ast` fails to import (unless the opt-in env above is set), so a misconfigured deploy fails loud instead of shipping weaker stubs.

## License

Copyright 2026 avkean. Licensed under [GPL-3.0](LICENSE).
