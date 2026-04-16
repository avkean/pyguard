"""v13.3.2 inner program — bootstrap-computed chain scrypt.

History.

  v13.3 prog_a was a 16-instruction seed-install program. SEEDS was
  a public constant in this module. An attacker with the pyguard
  source precomputed state_a analytically and skipped the entire
  prog_a execution on every guess (A27). The "chain" added no
  cryptographic work.

  v13.3.1 tried to fix this by putting OP_SCRYPT into prog_a on
  master-derived pw/salt slots. It killed A27 (state_key can no
  longer be precomputed) but A30 showed the per-wrong-guess cost
  only went up ~1.5x, not 2x. Why: on a wrong password, prog_a
  decrypts to 5 garbage bytes and OP_SCRYPT only fires on the ~2%
  of bytes that happen to mask to the OP_SCRYPT opcode value. The
  inner scrypt is effectively skipped on 98% of wrong guesses.

  v13.3.2 moves the inner scrypt OUT of the VM into the bootstrap:
  both defender and attacker compute `inner = scrypt(pw_in, salt_in)`
  unconditionally, and inject it into state[SLOT_SCRYPT_OUT] via
  init_slots. prog_a becomes a HLT-only no-op (just a format slot).
  state_key(state_a) still hashes slot 20 with length-framing, so
  it still depends on master via the inner scrypt. But now the
  inner scrypt is paid every guess, not conditional on OP_SCRYPT
  dispatch. Real 2x-per-guess amplification.

prog_b: the flag emitter. Re-seeds state with SEEDS (for the
XAB-over-zero assembly pattern), assembles the FLAG bytes into
SLOT_FLAG. The bootstrap is the sole emitter to stdout.
"""
from __future__ import annotations
from typing import List, Tuple
from . import vm_v13_3 as vm

Instr = Tuple

FLAG = b"FLAG{v13_3_3_typed_state_key_scope}"

# Slot map.
SLOT_SEED_ZERO = 0
SLOT_FLAG = 16
SLOT_SCRYPT_OUT = 20       # bootstrap injects scrypt(master_pw, master_salt)
                           # here via init_slots before run(prog_a).
SLOT_SCRATCH = 29


# SEEDS are used only by prog_b for the byte-assembly XAB-over-zero
# trick. They no longer have any role in state_key derivation — state_a
# is now master-dependent via scrypt. SEEDS being a public constant is
# fine here because prog_b is what actually needs them, and prog_b is
# decrypted under key_b (which depends on master via the scrypt chain).
SEEDS = [0, 0x3b, 0x17, 0xa5, 0x4c, 0x91, 0x82, 0x2d,
         0x6e, 0xd4, 0x5a, 0x79, 0xc0, 0x11, 0xee, 0x8b]


def _seed_state(prog: List[Instr]) -> None:
    for i, v in enumerate(SEEDS):
        prog.append((vm.OP_LDI, [i, v]))


def _assemble_bytes(prog: List[Instr], slot: int, data: bytes) -> None:
    prog.append((vm.OP_LDB, [slot]))
    for b in data:
        prog.append((vm.OP_LDI, [SLOT_SCRATCH, b]))
        prog.append((vm.OP_XAB, [slot, SLOT_SCRATCH, SLOT_SEED_ZERO]))


def build_prog_a() -> List[Instr]:
    """No-op program. The actual chain work is now done in the bootstrap.

    Why: v13.3.1 had OP_SCRYPT inside prog_a. On wrong passwords,
    prog_a decrypts to garbage bytes and OP_SCRYPT's masked dispatch
    only fires ~2% of the time. So 98% of wrong guesses skipped the
    inner scrypt entirely; the '2x per-guess cost' claim was false
    (A30 measured 1.46x). v13.3.2 moves the inner scrypt to the
    bootstrap where it ALWAYS fires, making the chain truly
    load-bearing per guess.

    prog_a is still run — its final state (slot 20 populated by the
    bootstrap's init_slots) is what state_key hashes. Keeping a
    prog_a run (even a trivial one) preserves the option to put
    more password-dependent transformations here in future.
    """
    prog: List[Instr] = []
    prog.append((vm.OP_HLT, []))
    return prog


def build_prog_b() -> List[Instr]:
    """Flag emitter.

    IMPORTANT: prog_b does NOT call `print`. The VM emits its result by
    leaving `FLAG` bytes in `state[SLOT_FLAG]`; the bootstrap reads that
    slot and is the only writer to stdout. This is deliberate: if the
    VM itself printed, right-pass output would be the FLAG (from VM's
    print) AND the FLAG (from bootstrap's state read) — doubled. And
    wrong-pass output would be empty. The two paths would diverge in
    size, which is a cheap oracle. Keeping prog_b side-effect-free
    makes the bootstrap's output length a function only of whatever
    ended up in `state[SLOT_FLAG]`, no matter the password.
    """
    prog: List[Instr] = []
    _seed_state(prog)
    _assemble_bytes(prog, SLOT_FLAG, FLAG)
    prog.append((vm.OP_HLT, []))
    return prog
