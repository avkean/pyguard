"""v13 register-machine VM runtime.

Design goals addressed (per docs/v13_architecture.md):

* Never `marshal.loads` the user program — no code object is ever
  constructed for user logic. User logic lives as a byte stream of
  instructions for this VM, which CPython never sees as a code object.
* Fused decode–execute: each instruction byte is XOR-demasked against
  a keystream derived from the *current register state* at the moment
  of decode. Static disassembly of the post-decrypt payload still
  produces gibberish until you correctly simulate state.
* Constants as trajectories: the `XAB` opcode appends a byte computed
  as `state[a] ^ state[b]` to a bytearray register. To materialise the
  string "print" the VM executes 5 XAB ops whose operands name
  different state slots; "print" is never contiguous in memory except
  for the single VM cycle that calls it.
* Name resolution by hash: the `RES` opcode looks up a callable in the
  enclosing scope by comparing SHA-256 prefixes, so the name string
  "print" / "input" / "chr" never appears in the stub.

This file is the *runtime*. The compiler that turns Python source into
a byte stream of these opcodes is in compiler.py. M0 ships a
hand-assembled hello-world program as a proof of end-to-end correctness
and as the target for the A14-style attack.

Opcode set (M0, minimal):

    0x00  NOP
    0x01  HLT
    0x10  LDI   reg, imm            ; state[reg] = imm (int 0..255)
    0x11  LDB   reg                 ; state[reg] = bytearray()
    0x20  XAB   reg_dst, a, b       ; state[dst].append(state[a] ^ state[b])
    0x21  APP   reg_dst, reg_src    ; state[dst].extend(state[src])
    0x30  RES   reg_dst, reg_name   ; state[dst] = resolve(state[name])
    0x40  CL0   reg_dst, reg_fn     ; state[dst] = state[fn]()
    0x41  CL1   reg_dst, reg_fn, reg_arg
                                    ; state[dst] = state[fn](state[arg])
    0x50  MOV   reg_dst, reg_src    ; state[dst] = state[src]
    0x60  JMP   u16_target          ; pc = target
    0x61  JIFZ  reg, u16_target     ; if state[reg] falsy: pc = target

Each instruction is length-prefixed; operands are single bytes.
`u16_target` is 2 bytes, big-endian.

Keystream: opcode byte `b` at position `pc` is demasked as
`b ^ mask(state, pc)` where mask is a SHA-256 rolling digest seeded
with the first N state bytes + pc. The mask advances as state mutates,
so the same underlying handler has different encoded bytes at
different execution points.
"""

from __future__ import annotations
import hashlib
import sys


# Public opcode constants (for the compiler and tests).
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
OP_EQ = 0x70   # dst = 1 if state[a] == state[b] else 0
OP_ENC = 0x71  # dst = state[src].encode('utf-8')
OP_SCRYPT = 0x80  # dst = scrypt(state[pw], state[salt]); fixed params
OP_XSTREAM = 0x81 # dst = bytes(c ^ k[i%len(k)] for i,c in state[ct])


# Trap: if the attacker has tracing installed, we silently mutate the
# keystream so that opcodes demask wrong and the program falls into a
# honeypot trajectory (future milestone). For M0 we stub this to 0.
def _trace_discriminator() -> int:
    t = sys.gettrace()
    p = sys.getprofile()
    if t is not None or p is not None:
        return 0x5A  # taint byte
    # Detect sys.monitoring tool registration (Python 3.12+).
    mon = getattr(sys, "monitoring", None)
    if mon is not None:
        for tid in range(6):
            try:
                if mon.get_tool(tid) is not None:
                    return 0x5A
            except Exception:
                pass
    return 0


def _mask(state_bytes: bytes, pc: int) -> int:
    """Keystream byte for position `pc`, seeded by the first 16 bytes
    of state + pc (big-endian 4) + the trace-discriminator byte.

    Under surveillance the discriminator is 0x5A, which silently
    corrupts every decoded opcode. Honest runs get 0 and decode
    correctly. M0 leaves honeypot-trajectory code for M4; for now
    surveillance causes the VM to hit OP_NOP or an undefined opcode and
    quietly halt."""
    h = hashlib.sha256()
    h.update(state_bytes[:16])
    h.update(pc.to_bytes(4, "big"))
    h.update(bytes([_trace_discriminator()]))
    return h.digest()[0]


def _state_snapshot(state: list) -> bytes:
    """Produce 16 bytes of state-derived keystream seed. Uses int
    slots; non-int slots contribute 0. This is the part of state that
    drives opcode decoding, so it must evolve as the program runs."""
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


def run(payload: bytes, scope: dict, nstate: int = 64) -> None:
    """Execute an encoded instruction stream.

    `payload`  : the keystream-masked opcode bytes (from the compiler).
    `scope`    : the dict used for name resolution (typically builtins +
                 any user-exported names).
    `nstate`   : number of state slots.
    """
    state: list = [0] * nstate
    pc = 0
    length = len(payload)

    while pc < length:
        seed = _state_snapshot(state)
        raw = payload[pc]
        op = raw ^ _mask(seed, pc)
        pc += 1

        if op == OP_NOP:
            continue
        if op == OP_HLT:
            return

        if op == OP_LDI:
            reg = payload[pc] ^ _mask(seed, pc); pc += 1
            imm = payload[pc] ^ _mask(seed, pc); pc += 1
            state[reg] = imm
            continue
        if op == OP_LDB:
            reg = payload[pc] ^ _mask(seed, pc); pc += 1
            state[reg] = bytearray()
            continue
        if op == OP_XAB:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            a = payload[pc] ^ _mask(seed, pc); pc += 1
            b = payload[pc] ^ _mask(seed, pc); pc += 1
            ba = state[dst]
            va = state[a] if isinstance(state[a], int) else 0
            vb = state[b] if isinstance(state[b], int) else 0
            ba.append((va ^ vb) & 0xFF)
            continue
        if op == OP_APP:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            src = payload[pc] ^ _mask(seed, pc); pc += 1
            state[dst].extend(state[src])
            continue
        if op == OP_RES:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            nm = payload[pc] ^ _mask(seed, pc); pc += 1
            target_hash = hashlib.sha256(bytes(state[nm])).digest()[:8]
            found = None
            for key, val in scope.items():
                if hashlib.sha256(key.encode("utf-8")).digest()[:8] == target_hash:
                    found = val
                    break
            state[dst] = found
            continue
        if op == OP_CL0:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            fn = payload[pc] ^ _mask(seed, pc); pc += 1
            state[dst] = state[fn]()
            continue
        if op == OP_CL1:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            fn = payload[pc] ^ _mask(seed, pc); pc += 1
            arg = payload[pc] ^ _mask(seed, pc); pc += 1
            argval = state[arg]
            # If arg is a bytearray/bytes, decode to str. Use
            # surrogateescape so arbitrary byte patterns never raise —
            # a raised UnicodeDecodeError would be a discriminator the
            # attacker could use to tell a wrong guess from a right one.
            if isinstance(argval, (bytes, bytearray)):
                argval = bytes(argval).decode("utf-8", errors="surrogateescape")
            state[dst] = state[fn](argval)
            continue
        if op == OP_MOV:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            src = payload[pc] ^ _mask(seed, pc); pc += 1
            state[dst] = state[src]
            continue
        if op == OP_JMP:
            hi = payload[pc] ^ _mask(seed, pc); pc += 1
            lo = payload[pc] ^ _mask(seed, pc); pc += 1
            pc = (hi << 8) | lo
            continue
        if op == OP_JIFZ:
            reg = payload[pc] ^ _mask(seed, pc); pc += 1
            hi = payload[pc] ^ _mask(seed, pc); pc += 1
            lo = payload[pc] ^ _mask(seed, pc); pc += 1
            if not state[reg]:
                pc = (hi << 8) | lo
            continue
        if op == OP_EQ:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            a = payload[pc] ^ _mask(seed, pc); pc += 1
            b = payload[pc] ^ _mask(seed, pc); pc += 1
            va = state[a]
            vb = state[b]
            # Normalise bytearray vs bytes so content-equal compare works.
            if isinstance(va, bytearray):
                va = bytes(va)
            if isinstance(vb, bytearray):
                vb = bytes(vb)
            state[dst] = 1 if va == vb else 0
            continue
        if op == OP_ENC:
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            src = payload[pc] ^ _mask(seed, pc); pc += 1
            v = state[src]
            if isinstance(v, str):
                state[dst] = v.encode("utf-8")
            elif isinstance(v, (bytes, bytearray)):
                state[dst] = bytes(v)
            else:
                state[dst] = b""
            continue
        if op == OP_SCRYPT:
            # Derive a 64-byte key from (pw, salt) using scrypt with
            # fixed, build-time-baked parameters. No branch on result.
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            pw = payload[pc] ^ _mask(seed, pc); pc += 1
            salt = payload[pc] ^ _mask(seed, pc); pc += 1
            pw_b = state[pw]
            salt_b = state[salt]
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
            # N=16384, r=8, p=1 — scrypt work factor (tunable at build).
            state[dst] = hashlib.scrypt(pw_b, salt=salt_b, n=16384, r=8, p=1, dklen=64)
            continue
        if op == OP_XSTREAM:
            # state[dst] = state[ct] XOR state[key] (key repeats if short).
            # Unconditional; wrong key → high-entropy gibberish, no branch.
            dst = payload[pc] ^ _mask(seed, pc); pc += 1
            ct = payload[pc] ^ _mask(seed, pc); pc += 1
            key = payload[pc] ^ _mask(seed, pc); pc += 1
            ct_b = state[ct]
            key_b = state[key]
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
            continue

        # Unknown opcode → silent halt. Under surveillance this is what
        # the trace-discriminator path produces: decoded opcodes don't
        # match any handler, we return without producing real output.
        return
