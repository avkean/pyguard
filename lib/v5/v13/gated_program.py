"""M0 gated program — the exact challenge shape the red team pointed at.

Pseudocode:
    input_str = input()
    input_bytes = input_str.encode('utf-8')
    if input_bytes == EXPECTED_PASSWORD:
        print(FLAG)
    else:
        print(NOPE)

EXPECTED_PASSWORD and FLAG are both assembled as byte trajectories
(XOR pairs from seed slots). The program has a local equality check
(OP_EQ) and a conditional branch (OP_JIFZ). This is deliberately the
"client-side verifier" pattern the red team identified as the central
weakness, so we can measure exactly how much protection the v13 VM
provides — and exactly which attacks break it.

Slot map:
    0..15          seed slots (LDI at start, never mutated after)
    16             "input" name bytearray
    17             input resolved
    18             guess (str from input())
    19             guess bytes
    20             "print" name bytearray
    21             print resolved
    22             "encode" — not used, kept for documentation
    23             PASSWORD (trajectory-assembled bytes)
    24             EQ result
    25             FLAG (trajectory-assembled bytes)
    26             NOPE (trajectory-assembled bytes)
    27             scratch (print return value)
"""
from __future__ import annotations
from typing import List, Tuple
from . import vm

Instr = Tuple

PASSWORD = b"correcthorse"
FLAG = b"FLAG{v13_m0_gated_local_check}"
NOPE = b"Access denied."


def _find_seeds(needed: set):
    """Greedy seed search — picks 16 byte values whose pairwise XORs
    cover every byte in `needed`. Slot 0 fixed at 0 so XOR with 0
    yields raw seed values."""
    palette = sorted({
        *(i for i in range(64)),
        *(1 << k for k in range(8)),
        *((1 << k) - 1 for k in range(1, 8)),
        *(i ^ 0x70 for i in range(16)),
        *(i ^ 0x6c for i in range(16)),
        *(i ^ 0x41 for i in range(16)),
        *(i ^ 0x20 for i in range(32)),
        *(i ^ 0x30 for i in range(32)),
    } - {0}) + [0]
    seeds = [0]
    covered = set()
    while len(seeds) < 16:
        best, best_gain = None, -1
        for cand in palette:
            if cand in seeds:
                continue
            gain = sum(1 for ex in seeds if (cand ^ ex) in needed and (cand ^ ex) not in covered)
            if gain > best_gain:
                best_gain, best = gain, cand
        if best is None:
            break
        seeds.append(best)
        for ex in seeds[:-1]:
            covered.add(best ^ ex)
    missing = needed - covered
    if missing:
        raise RuntimeError(f"seed search failed; missing: {missing}")
    return seeds


_NEEDED = set(b"input" + b"print" + PASSWORD + FLAG + NOPE)
SEED = _find_seeds(_NEEDED)


def _pair(target: int):
    for i in range(len(SEED)):
        for j in range(len(SEED)):
            if (SEED[i] ^ SEED[j]) == target:
                return i, j
    raise ValueError(target)


def _assemble_bytes_into(prog: List[Instr], slot: int, data: bytes):
    prog.append((vm.OP_LDB, [slot]))
    for b in data:
        i, j = _pair(b)
        prog.append((vm.OP_XAB, [slot, i, j]))


def build_program() -> List[Instr]:
    prog: List[Instr] = []
    for i in range(16):
        prog.append((vm.OP_LDI, [i, SEED[i]]))

    # Assemble "input", resolve, call → slot 18 (str).
    _assemble_bytes_into(prog, 16, b"input")
    prog.append((vm.OP_RES, [17, 16]))
    prog.append((vm.OP_CL0, [18, 17]))

    # Encode to bytes → slot 19.
    prog.append((vm.OP_ENC, [19, 18]))

    # Assemble PASSWORD → slot 23.
    _assemble_bytes_into(prog, 23, PASSWORD)

    # Compare → slot 24.
    prog.append((vm.OP_EQ, [24, 19, 23]))

    # Assemble "print" → slot 20; resolve → slot 21.
    _assemble_bytes_into(prog, 20, b"print")
    prog.append((vm.OP_RES, [21, 20]))

    # Branch: if EQ == 0 → jump to DENIED.
    prog.append((vm.OP_JIFZ, [24, ("LBL", "DENIED")]))

    # Success path: assemble FLAG → slot 25; print.
    _assemble_bytes_into(prog, 25, FLAG)
    prog.append((vm.OP_CL1, [27, 21, 25]))
    prog.append((vm.OP_JMP, [("LBL", "END")]))

    # Denied path: assemble NOPE → slot 26; print.
    prog.append(("LABEL", "DENIED"))
    _assemble_bytes_into(prog, 26, NOPE)
    prog.append((vm.OP_CL1, [27, 21, 26]))

    prog.append(("LABEL", "END"))
    prog.append((vm.OP_HLT, []))
    return prog
