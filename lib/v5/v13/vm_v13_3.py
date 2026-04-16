"""v13.3 register-machine VM runtime.

Differences from `vm.py` (v13.0–v13.2):

  1. **Total dispatch.** Unknown opcode bytes no longer halt the VM.
     They fall through as NOP. Every byte value of every operand is
     valid (register indices are taken `% nstate`). A payload of
     uniformly-random bytes runs to its end without raising and
     without silent-halt-on-unknown — so wrong-password decryption
     produces a *different-output*, not a *different-behavior*,
     discriminator.

  2. **Exception-wrapped external calls.** OP_RES / OP_CL0 / OP_CL1 /
     OP_ENC catch every exception. A failed name lookup or a call on
     a non-callable state slot no longer raises to the bootstrap — it
     leaves the destination slot as `None` or empty bytes and the VM
     continues. The point is to remove crash-based oracles: wrong
     keys must be indistinguishable from right keys except by the
     semantic content of the emitted output.

  3. **Hard instruction cap.** `run(prog, scope, max_steps=20000)`
     halts after `max_steps` if the program hasn't hit HLT. Prevents
     wrong-payload infinite loops (especially through JMP). Does not
     raise — silent halt.

  4. **Two-stage chained execution.** `run_chained(prog_a, prog_b_ct,
     nonce_b, scope)` runs `prog_a`, takes a state snapshot, derives
     a key from it, decrypts `prog_b_ct` under that key, then runs
     `prog_b`. The attacker cannot run `prog_b` without first running
     `prog_a` correctly, which requires the right `prog_a` plaintext,
     which requires the right `master_key`, which requires the right
     password. No structural oracle on `prog_b_ct` reveals whether
     the attempt was on the right path.

  5. **No `_trace_discriminator`.** It was never exercised in v13.2
     and the tracing check is a static-analysis beacon
     (`sys.gettrace`, `sys.monitoring`). Dropped.

The opcode constants are identical to v13's so prior programs are
byte-compatible modulo the per-build permutation performed by
`diversify.render_vm_source`.
"""
from __future__ import annotations
import hashlib


OP_NOP = 0x00
OP_HLT = 0x01
OP_LDI = 0x10
OP_LDB = 0x11
OP_XAB = 0x20
OP_APP = 0x21
OP_RES = 0x30
OP_CL0 = 0x40
OP_CL1 = 0x41
OP_MOV = 0x50
OP_JMP = 0x60
OP_JIFZ = 0x61
OP_EQ = 0x70
OP_ENC = 0x71
OP_SCRYPT = 0x80
OP_XSTREAM = 0x81

# Per-build keystream discriminator byte. Overwritten by
# `diversify.render_vm_source_v13_3` when the VM source is baked
# into a stub; left at 0 for the reference module.
_DISC = 0x00


def _mask(state_bytes: bytes, pc: int) -> int:
    h = hashlib.sha256()
    h.update(state_bytes[:16])
    h.update(pc.to_bytes(4, "big"))
    h.update(bytes([_DISC]))
    return h.digest()[0]


def _state_snapshot(state: list) -> bytes:
    out = bytearray(16)
    for i in range(16):
        v = state[i] if i < len(state) else 0
        if isinstance(v, int):
            out[i] = v & 0xFF
        elif isinstance(v, (bytes, bytearray)) and len(v) > 0:
            out[i] = v[0] & 0xFF
        else:
            out[i] = 0
    return bytes(out)


def _step(payload: bytes, pc: int, state: list, nstate: int,
          scope: dict) -> int:
    """Decode and execute one instruction. Returns the new pc (or -1
    to request halt). Never raises."""
    seed = _state_snapshot(state)
    length = len(payload)
    if pc >= length:
        return -1

    def _read():
        nonlocal pc
        b = payload[pc] ^ _mask(seed, pc)
        pc += 1
        return b

    def _reg():
        return _read() % nstate

    try:
        op = _read()

        if op == OP_NOP:
            return pc
        if op == OP_HLT:
            return -1

        if op == OP_LDI:
            reg = _reg(); imm = _read()
            state[reg] = imm
            return pc
        if op == OP_LDB:
            reg = _reg()
            state[reg] = bytearray()
            return pc
        if op == OP_XAB:
            dst = _reg(); a = _reg(); b = _reg()
            ba = state[dst]
            if not isinstance(ba, bytearray):
                return pc
            va = state[a] if isinstance(state[a], int) else 0
            vb = state[b] if isinstance(state[b], int) else 0
            ba.append((va ^ vb) & 0xFF)
            return pc
        if op == OP_APP:
            dst = _reg(); src = _reg()
            d = state[dst]; s = state[src]
            if isinstance(d, bytearray) and isinstance(s, (bytes, bytearray)):
                d.extend(s)
            return pc
        if op == OP_RES:
            dst = _reg(); nm = _reg()
            nm_val = state[nm]
            if isinstance(nm_val, (bytes, bytearray)):
                target_hash = hashlib.sha256(bytes(nm_val)).digest()[:8]
                found = None
                for key, val in scope.items():
                    try:
                        if hashlib.sha256(key.encode("utf-8")).digest()[:8] == target_hash:
                            found = val
                            break
                    except Exception:
                        pass
                state[dst] = found
            else:
                state[dst] = None
            return pc
        if op == OP_CL0:
            dst = _reg(); fn = _reg()
            fnv = state[fn]
            try:
                state[dst] = fnv() if callable(fnv) else None
            except Exception:
                state[dst] = None
            return pc
        if op == OP_CL1:
            dst = _reg(); fn = _reg(); arg = _reg()
            fnv = state[fn]
            argval = state[arg]
            if isinstance(argval, (bytes, bytearray)):
                try:
                    argval = bytes(argval).decode("utf-8", errors="surrogateescape")
                except Exception:
                    argval = ""
            try:
                state[dst] = fnv(argval) if callable(fnv) else None
            except Exception:
                state[dst] = None
            return pc
        if op == OP_MOV:
            dst = _reg(); src = _reg()
            state[dst] = state[src]
            return pc
        if op == OP_JMP:
            hi = _read(); lo = _read()
            return ((hi << 8) | lo) % max(1, length)
        if op == OP_JIFZ:
            reg = _reg(); hi = _read(); lo = _read()
            if not state[reg]:
                return ((hi << 8) | lo) % max(1, length)
            return pc
        if op == OP_EQ:
            dst = _reg(); a = _reg(); b = _reg()
            va = state[a]; vb = state[b]
            if isinstance(va, bytearray):
                va = bytes(va)
            if isinstance(vb, bytearray):
                vb = bytes(vb)
            try:
                state[dst] = 1 if va == vb else 0
            except Exception:
                state[dst] = 0
            return pc
        if op == OP_ENC:
            dst = _reg(); src = _reg()
            v = state[src]
            try:
                if isinstance(v, str):
                    state[dst] = v.encode("utf-8")
                elif isinstance(v, (bytes, bytearray)):
                    state[dst] = bytes(v)
                else:
                    state[dst] = b""
            except Exception:
                state[dst] = b""
            return pc
        if op == OP_SCRYPT:
            dst = _reg(); pw = _reg(); salt = _reg()
            pw_b = state[pw]; salt_b = state[salt]
            if isinstance(pw_b, (bytes, bytearray)):
                pw_b = bytes(pw_b)
            elif isinstance(pw_b, str):
                pw_b = pw_b.encode("utf-8")
            else:
                pw_b = b""
            if isinstance(salt_b, (bytes, bytearray)):
                salt_b = bytes(salt_b)
            else:
                salt_b = b""
            try:
                state[dst] = hashlib.scrypt(pw_b, salt=salt_b, n=16384, r=8, p=1, dklen=64)
            except Exception:
                state[dst] = b""
            return pc
        if op == OP_XSTREAM:
            dst = _reg(); ct = _reg(); key = _reg()
            ct_b = state[ct]; key_b = state[key]
            if isinstance(ct_b, (bytes, bytearray)):
                ct_b = bytes(ct_b)
            else:
                ct_b = b""
            if isinstance(key_b, (bytes, bytearray)):
                key_b = bytes(key_b)
            else:
                key_b = b""
            if not key_b:
                state[dst] = ct_b
            else:
                klen = len(key_b)
                state[dst] = bytes(c ^ key_b[i % klen] for i, c in enumerate(ct_b))
            return pc

        # Unknown opcode: total-dispatch NOP. No silent halt.
        return pc
    except Exception:
        # Any unexpected failure -> NOP-equivalent. Never propagate.
        return pc if pc <= length else -1


def run(payload: bytes, scope: dict, nstate: int = 64,
        max_steps: int = 20000, init_slots: dict | None = None) -> list:
    """Execute `payload`. Returns the final state (for chaining).

    `init_slots` maps slot index -> initial value. Used by the v13.3.1
    bootstrap to inject master-derived bytes into state before prog_a
    runs, so that state_key(state_a) becomes a function of master. This
    closes A27 (the "prog_a is a seed-install no-op" attack) by making
    prog_a perform a non-trivial, master-dependent computation
    (OP_SCRYPT in slot 20 on pw/salt slots 30/31).
    """
    state: list = [0] * nstate
    if init_slots:
        for slot, value in init_slots.items():
            state[slot % nstate] = value
    pc = 0
    steps = 0
    while pc >= 0 and pc < len(payload) and steps < max_steps:
        pc = _step(payload, pc, state, nstate, scope)
        steps += 1
    return state


def state_key(state: list) -> bytes:
    """Derive a 32-byte key from the full state for chained-decrypt.

    v13.3.1: every byte blob fed into the hash is length-framed with a
    4-byte big-endian length prefix, and every slot is domain-separated
    with a 1-byte slot index. Closes the v13.3 hygiene bug where
    `state[16]=b"AB", state[17]=b"CD"` hashed identically to
    `state[16]=b"ABCD", state[17]=b""`.

    v13.3.3 (F2): each slot is also type-tagged. Without type tags,
    int=0, bytes=b"\\x00", and None all serialized to the same bytes
    (\\x00\\x00\\x00\\x01\\x00 or the int branch's equivalent), so three
    distinct state shapes had the same key_b. Now int / bytes / other
    are separated by a leading type byte: 0x01 int, 0x02 bytes,
    0x03 other. Right-pass key_b changes vs v13.3.2 (it's a new
    cryptographic derivation); wrong-pass aliasing between those three
    classes is eliminated.
    """
    h = hashlib.sha256()
    h.update(b"v13_3_3_state_key")  # domain tag for version separation
    # First 16 state bytes are the mask-driving slots (first-byte snapshot).
    snap = _state_snapshot(state)
    h.update(b"\x00")  # domain tag: "snapshot"
    h.update(len(snap).to_bytes(4, "big"))
    h.update(snap)
    # Slots 16..31, type-tagged, length-framed, and slot-tagged.
    for i in range(16, min(32, len(state))):
        v = state[i] if i < len(state) else 0
        h.update(bytes([i & 0xFF]))  # slot tag
        if isinstance(v, int):
            h.update(b"\x01")  # type: int
            h.update((v & 0xFF).to_bytes(1, "big"))
        elif isinstance(v, (bytes, bytearray)):
            vb = bytes(v)
            h.update(b"\x02")  # type: bytes
            h.update(len(vb).to_bytes(4, "big"))
            h.update(vb)
        else:
            h.update(b"\x03")  # type: other (None, str, etc.)
    return h.digest()
