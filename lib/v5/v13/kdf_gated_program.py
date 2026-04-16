"""M1 KDF-gated program — the v13-next design.

No local compare. No branch on secrets. Unconditional decrypt-and-print.
Wrong password yields high-entropy garbage; right password yields the
flag. The KDF (scrypt) is the work factor.

Shape:
    guess_str   = input()
    guess_bytes = guess_str.encode('utf-8')
    salt        = <embedded 16 random bytes, trajectory-assembled>
    key         = scrypt(guess_bytes, salt, N=16384, r=8, p=1, dklen=64)
    ct          = <embedded ciphertext bytes, trajectory-assembled>
                  (ct == FLAG XOR scrypt(PASSWORD, salt) at build time)
    plaintext   = xstream(ct, key)     # ct XOR key (key repeats if short)
    print(plaintext)

No OP_EQ. No OP_JIFZ on secrets. No "Access denied" fallback. The
program runs the same op sequence regardless of input.

Slot map:
    0..15    seed slots (LDI init so slot 0 == 0; rest seed keystream)
    16       "input" name bytearray
    17       input resolved
    18       guess (str from input())
    19       guess bytes (utf-8 encoded)
    20       salt bytearray
    21       key (scrypt output)
    22       ciphertext bytearray
    23       plaintext bytes (after OP_XSTREAM)
    24       "print" name bytearray
    25       print resolved
    26       print return value
    30       scratch int (used by LDI+XAB constant-assembly pattern)

Byte assembly pattern for arbitrary byte values:

    LDI  30, <byte>
    XAB  target, 30, 0          ; state[0] == 0 ⇒ appends <byte>

This works for any 0..255 byte, unlike the seed-pair approach which
only spans ~120 distinct values. The operand stream is still keystream-
masked (state-dependent), so A17-style simulation still works — but
the attacker is only recovering the CIPHERTEXT and SALT, not the flag.
Deriving the flag requires inverting scrypt under the correct password.
"""
from __future__ import annotations
import hashlib
import os
from typing import List, Tuple
from . import vm

Instr = Tuple

# The test password and flag. A real deployment would parameterise these.
PASSWORD = b"correcthorse"
FLAG = b"FLAG{v13_m1_kdf_gated_no_branch}"

# Scrypt params must match vm.OP_SCRYPT handler (N=16384, r=8, p=1, dklen=64).
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64

# Slot constants.
SLOT_SEED_ZERO = 0              # invariant: state[0] == 0
SLOT_INPUT_NAME = 16
SLOT_INPUT_FN = 17
SLOT_GUESS_STR = 18
SLOT_GUESS_BYTES = 19
SLOT_SALT = 20
SLOT_KEY = 21
SLOT_CT = 22
SLOT_PT = 23
SLOT_PRINT_NAME = 24
SLOT_PRINT_FN = 25
SLOT_PRINT_RET = 26
SLOT_SCRATCH = 30


def _pick_seeds():
    """Pick 16 seed slot values. Slot 0 == 0 (required invariant).
    The other 15 can be anything non-zero; pick them deterministically
    to vary the keystream. A build-time random seed could be used for
    per-build diversification (M4+).
    """
    seeds = [0] * 16
    # Spread out to give the state snapshot some entropy — the keystream
    # SHA-256 will absorb any variation.
    seeds[1:] = [0x3b, 0x17, 0xa5, 0x4c, 0x91, 0x82, 0x2d, 0x6e,
                 0xd4, 0x5a, 0x79, 0xc0, 0x11, 0xee, 0x8b]
    return seeds


def _assemble_bytes(prog: List[Instr], target_slot: int, data: bytes):
    """Emit ops that append `data` byte-by-byte into bytearray in
    target_slot, using the LDI+XAB scratch pattern so any byte value is
    encodable."""
    prog.append((vm.OP_LDB, [target_slot]))
    for b in data:
        prog.append((vm.OP_LDI, [SLOT_SCRATCH, b]))
        prog.append((vm.OP_XAB, [target_slot, SLOT_SCRATCH, SLOT_SEED_ZERO]))


def _xor(a: bytes, b: bytes) -> bytes:
    if len(b) == 0:
        return a
    return bytes(ch ^ b[i % len(b)] for i, ch in enumerate(a))


def build_program_and_meta() -> Tuple[List[Instr], dict]:
    """Return (program, metadata). Metadata captures the build-time
    salt and ciphertext for introspection during testing.
    """
    seeds = _pick_seeds()
    salt = os.urandom(16)

    # Derive key from (correct password, salt).
    true_key = hashlib.scrypt(
        PASSWORD, salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    # Ciphertext = FLAG XOR key-prefix. FLAG must fit in dklen to avoid
    # keystream reuse.
    if len(FLAG) > _SCRYPT_DKLEN:
        raise ValueError("FLAG longer than dklen — would reuse keystream")
    ct = _xor(FLAG, true_key)

    prog: List[Instr] = []

    # 1. Init 16 seed slots.
    for i, v in enumerate(seeds):
        prog.append((vm.OP_LDI, [i, v]))

    # 2. Assemble b"input", resolve, call → guess_str.
    _assemble_bytes(prog, SLOT_INPUT_NAME, b"input")
    prog.append((vm.OP_RES, [SLOT_INPUT_FN, SLOT_INPUT_NAME]))
    prog.append((vm.OP_CL0, [SLOT_GUESS_STR, SLOT_INPUT_FN]))

    # 3. ENC: guess_str → guess_bytes.
    prog.append((vm.OP_ENC, [SLOT_GUESS_BYTES, SLOT_GUESS_STR]))

    # 4. Assemble salt into slot 20.
    _assemble_bytes(prog, SLOT_SALT, salt)

    # 5. OP_SCRYPT: key = scrypt(guess_bytes, salt).
    prog.append((vm.OP_SCRYPT, [SLOT_KEY, SLOT_GUESS_BYTES, SLOT_SALT]))

    # 6. Assemble ciphertext into slot 22.
    _assemble_bytes(prog, SLOT_CT, ct)

    # 7. OP_XSTREAM: pt = ct XOR key.
    prog.append((vm.OP_XSTREAM, [SLOT_PT, SLOT_CT, SLOT_KEY]))

    # 8. Assemble b"print", resolve, call print(pt).
    _assemble_bytes(prog, SLOT_PRINT_NAME, b"print")
    prog.append((vm.OP_RES, [SLOT_PRINT_FN, SLOT_PRINT_NAME]))
    prog.append((vm.OP_CL1, [SLOT_PRINT_RET, SLOT_PRINT_FN, SLOT_PT]))

    prog.append((vm.OP_HLT, []))

    meta = {
        "password": PASSWORD,
        "flag": FLAG,
        "salt": salt,
        "ciphertext": ct,
        "scrypt_params": (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DKLEN),
    }
    return prog, meta


def build_program() -> List[Instr]:
    prog, _meta = build_program_and_meta()
    return prog
