"""M0 hand-rolled hello-world register program.

Demonstrates:
  * The string "hello, world" is never a literal anywhere. It is
    assembled byte-by-byte by XAB operations whose operands are state
    slots seeded with small constants.
  * The function name "print" is never a literal. It's assembled the
    same way and resolved by SHA-256-prefix match.

The entire program is one straight-line sequence (no jumps).
"""
from __future__ import annotations
from typing import List, Tuple
from . import vm

Instr = Tuple[int, List[int]]

# ---------------------------------------------------------------------
# Slot map (chosen to live above the 16-slot keystream window where
# possible, so mutations to them don't perturb opcode masking):
#
#   slots 0..15  : keystream seed bytes; we set these to small values
#                  that drive the mask stream deterministically.
#   slot 20      : "print" name bytearray (assembled)
#   slot 21      : "print" resolved callable
#   slot 22      : "hello, world" message bytearray (assembled)
#   slot 23      : result of print (always None; we discard)
#
# The trick: we seed slots 0..15 with small integer values such that
# XOR pairs among them produce the byte values we need for both
# "print" and "hello, world". This gives a concrete, deterministic
# trajectory that the VM can replay but that a static reader of the
# encoded payload bytes cannot.
# ---------------------------------------------------------------------


# Pairs to build "print" (bytes 0x70 0x72 0x69 0x6e 0x74) and
# "hello, world" (0x68 0x65 0x6c 0x6c 0x6f 0x2c 0x20 0x77 0x6f 0x72
# 0x6c 0x64). We pick seed values and XOR pairs by construction.
#
# Seed layout: slot i holds value SEED[i]. Then to produce target byte
# T we pick slots (i,j) such that SEED[i] ^ SEED[j] == T. We use a
# modest palette that covers every needed target.

# Seed selection: we need XOR pairs covering every byte in "print"
# and "hello, world". The 17 distinct target bytes are searched against
# candidate seed sets until one works. For M0 this is a small, static
# computation; for user programs the compiler (M1) will pick seeds
# per-build.

NEEDED = set(b"print" + b"hello, world")


def _find_seeds():
    import itertools
    # Start from a palette of likely-useful bytes: small ints, powers
    # of 2, and complements.
    palette = sorted({
        *(i for i in range(32)),
        *(1 << k for k in range(8)),
        *((1 << k) - 1 for k in range(1, 8)),
        *(i ^ 0x70 for i in range(16)),
        *(i ^ 0x6c for i in range(16)),
    } - {0})  # slot 0 is reserved for keystream seed byte 0
    # Greedy: pick the seed that adds the most coverage, repeat.
    seeds = [0]  # slot 0 fixed at 0
    covered = set()
    # With slot 0 == 0 in the set, state[0] ^ state[i] == state[i], so
    # every seed value itself becomes a single-XOR target.
    while len(seeds) < 16:
        best = None
        best_gain = -1
        for cand in palette:
            if cand in seeds:
                continue
            gain = 0
            for existing in seeds:
                v = cand ^ existing
                if v in NEEDED and v not in covered:
                    gain += 1
            if gain > best_gain:
                best_gain = gain
                best = cand
        if best is None:
            break
        seeds.append(best)
        for existing in seeds[:-1]:
            covered.add(best ^ existing)
    # Check all NEEDED are reachable.
    missing = NEEDED - covered
    if missing:
        raise RuntimeError(f"seed search failed; missing: {missing}")
    return seeds


SEED = _find_seeds()


def _find_pair(target: int):
    for i in range(len(SEED)):
        for j in range(len(SEED)):
            if (SEED[i] ^ SEED[j]) == target:
                return i, j
    raise ValueError(f"no XOR pair in SEED for target {target:#x}")


def build_program() -> List[Instr]:
    prog: List[Instr] = []

    # Seed slots 0..15.
    for i in range(16):
        prog.append((vm.OP_LDI, [i, SEED[i]]))

    # Allocate slot 20 as bytearray, then assemble "print" into it.
    prog.append((vm.OP_LDB, [20]))
    for ch in b"print":
        a, b = _find_pair(ch)
        prog.append((vm.OP_XAB, [20, a, b]))

    # Resolve: state[21] = scope[key where sha256(key)[:8] == sha256(state[20])[:8]]
    prog.append((vm.OP_RES, [21, 20]))

    # Allocate slot 22, assemble "hello, world".
    prog.append((vm.OP_LDB, [22]))
    for ch in b"hello, world":
        a, b = _find_pair(ch)
        prog.append((vm.OP_XAB, [22, a, b]))

    # Call state[21](state[22]) → state[23].
    prog.append((vm.OP_CL1, [23, 21, 22]))

    prog.append((vm.OP_HLT, []))
    return prog
