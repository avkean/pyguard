"""v13.2 inner program.

Runs inside the encrypted VM blob. The outer bootstrap handles the
password gate by deriving the master key; if the user's password is
wrong, the blob decrypts to garbage and `exec` either fails (caught)
or produces nothing, after which the bootstrap emits its deterministic
pseudo-random output. So the inner program doesn't repeat a password
check — it unconditionally emits its payload.

For a flag challenge, the payload is `FLAG{...}`. For a real
user-program obfuscation, the payload would be whatever the user's
Python does. The architecture is agnostic.
"""
from __future__ import annotations
from typing import List, Tuple
from . import vm

Instr = Tuple

FLAG = b"FLAG{v13_2_encrypted_vm_bootstrap}"

# Slot map — kept simple since password gating is handled by outer.
SLOT_SEED_ZERO = 0
SLOT_FLAG = 16
SLOT_PRINT_NAME = 17
SLOT_PRINT_FN = 18
SLOT_PRINT_RET = 19
SLOT_SCRATCH = 30


def _seeds():
    # Slot 0 must be 0 for the LDI+XAB-over-zero append pattern.
    # Other 15 seeds can be anything — here a fixed but non-trivial
    # sequence chosen to give the keystream some entropy. (Per-build
    # diversification of these seeds is a v13.3+ concern.)
    return [0, 0x3b, 0x17, 0xa5, 0x4c, 0x91, 0x82, 0x2d,
            0x6e, 0xd4, 0x5a, 0x79, 0xc0, 0x11, 0xee, 0x8b]


def _assemble_bytes(prog: List[Instr], slot: int, data: bytes):
    prog.append((vm.OP_LDB, [slot]))
    for b in data:
        prog.append((vm.OP_LDI, [SLOT_SCRATCH, b]))
        prog.append((vm.OP_XAB, [slot, SLOT_SCRATCH, SLOT_SEED_ZERO]))


def build_program() -> List[Instr]:
    prog: List[Instr] = []
    seeds = _seeds()
    for i, v in enumerate(seeds):
        prog.append((vm.OP_LDI, [i, v]))

    _assemble_bytes(prog, SLOT_FLAG, FLAG)
    _assemble_bytes(prog, SLOT_PRINT_NAME, b"print")
    prog.append((vm.OP_RES, [SLOT_PRINT_FN, SLOT_PRINT_NAME]))
    prog.append((vm.OP_CL1, [SLOT_PRINT_RET, SLOT_PRINT_FN, SLOT_FLAG]))
    prog.append((vm.OP_HLT, []))
    return prog
