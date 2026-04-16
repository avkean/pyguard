"""v13.2 per-build diversification.

The v13.1 VM shipped stable opcode values (OP_LDI = 0x10 in every
build, etc.) and plaintext handler source. A21 exploits both:
handler classification runs by matching handler body patterns that
are identical across builds.

Diversification here changes two things per build, deterministically
from a build seed:

* Opcode byte values — `OP_LDI` could be 0x3a in build A and 0xc7 in
  build B. An attacker cannot memorise the map across builds.
* Keystream discriminator byte — the byte that gets hashed into
  `_mask` after the state+pc; differs per build. This changes the
  entire keystream without touching structure.

Everything else (dispatch structure, slot count, snapshot width) is
unchanged at v13.2. v13.3+ will extend this further.

The diversification seed itself is stored inside the encrypted VM
blob (the bootstrap doesn't need to know it; it just execs the
decrypted VM source which already has the per-build constants baked
in). This is deliberately non-secret from an attacker who has the
correct password (they can read the decrypted VM source). The
adversary v13.2 targets is an attacker WITHOUT the correct password.
"""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from typing import Dict


OPCODE_NAMES = (
    "NOP", "HLT", "LDI", "LDB", "XAB", "APP", "RES", "CL0",
    "CL1", "MOV", "JMP", "JIFZ", "EQ", "ENC", "SCRYPT", "XSTREAM",
)


@dataclass(frozen=True)
class BuildProfile:
    """Per-build diversification parameters."""
    seed: bytes
    opcode_map: Dict[str, int]      # name -> byte value
    discriminator: int              # keystream mixing byte

    @classmethod
    def from_seed(cls, seed: bytes) -> "BuildProfile":
        if len(seed) < 16:
            raise ValueError("seed must be at least 16 bytes")
        # Deterministic permutation of 0..255 from SHA-256 stream.
        pool = list(range(256))
        stream = b""
        i = 0
        while len(stream) < 2048:
            stream += hashlib.sha256(seed + b"opcode-perm" + i.to_bytes(4, "big")).digest()
            i += 1
        # Fisher-Yates shuffle driven by `stream`.
        idx = 0
        for k in range(len(pool) - 1, 0, -1):
            if idx + 2 > len(stream):
                stream += hashlib.sha256(seed + b"opcode-perm-ext" + idx.to_bytes(4, "big")).digest()
            j = int.from_bytes(stream[idx:idx+2], "big") % (k + 1)
            idx += 2
            pool[k], pool[j] = pool[j], pool[k]
        opcode_map = {name: pool[i] for i, name in enumerate(OPCODE_NAMES)}
        # v13.3.3 (F3): rejection sampling to avoid disc == 0 without the
        # bias of the old `if disc == 0: disc = 1` rule. That rule made
        # disc == 1 appear with probability 2/256 and all other non-zero
        # values with probability 1/256 — a cryptographically measurable
        # bias in the keystream-discriminator distribution. We now pull
        # fresh bytes from sha256(seed || "disc" || counter) until we get
        # a non-zero byte, giving every value in 1..255 exactly 1/255
        # probability. The reason we still avoid 0 at all: the reference
        # (unrendered) vm_v13_3 module ships with _DISC = 0, so disc = 0
        # would produce keystream identical to the reference — a trivial
        # byte-equality oracle across builds.
        disc = 0
        counter = 0
        while disc == 0:
            disc = hashlib.sha256(
                seed + b"disc" + counter.to_bytes(4, "big")
            ).digest()[0]
            counter += 1
        return cls(seed=seed, opcode_map=opcode_map, discriminator=disc)


# ---------------------------------------------------------------------------
# VM source rendering: take the reference lib/v5/v13/vm.py and rewrite the
# opcode constants + mask-discriminator byte.

_OPCODE_LINE_RE = re.compile(
    r"^(OP_(?P<name>[A-Z0-9]+)\s*=\s*)0x[0-9a-fA-F]+(.*)$",
    re.MULTILINE,
)
_DISC_LINE_RE = re.compile(
    r'h\.update\(bytes\(\[_trace_discriminator\(\)\]\)\)'
)


_DISC_V13_3_RE = re.compile(r"^_DISC\s*=\s*0x[0-9a-fA-F]+", re.MULTILINE)


def render_vm_source_v13_3(profile: BuildProfile, base_source: str) -> str:
    """Rewrite the v13.3 VM runtime source (vm_v13_3.py content):

        OP_NAME = 0xNN   →   OP_NAME = 0xMM    (per-build)
        _DISC   = 0x00   →   _DISC   = 0xXX    (per-build)

    v13.3 has no `_trace_discriminator` function — the discriminator
    is a module-level constant baked in per build.
    """
    lines = base_source.splitlines()
    out = []
    for ln in lines:
        m = _OPCODE_LINE_RE.match(ln)
        if m and m.group("name") in profile.opcode_map:
            new = f"{m.group(1)}{profile.opcode_map[m.group('name')]:#04x}{m.group(3)}"
            out.append(new)
        else:
            out.append(ln)
    src = "\n".join(out)
    src = _DISC_V13_3_RE.sub(f"_DISC = {profile.discriminator:#04x}", src)
    return src


def render_vm_source(profile: BuildProfile, base_source: str) -> str:
    """Rewrite `base_source` (the VM runtime) so opcode constants and
    the keystream discriminator match `profile`.

    The base source is expected to be `lib/v5/v13/vm.py`'s content.
    We rewrite:

        OP_NAME = 0xNN        →   OP_NAME = 0xMM     (per-build)
        bytes([_trace_discriminator()])
                              →   bytes([_trace_discriminator() ^ DISC])

    The `_trace_discriminator ^ DISC` XOR keeps the honest-run byte
    equal to `DISC` (since _trace_discriminator returns 0 on an honest
    run), and under surveillance it becomes `0x5A ^ DISC` — still a
    taint, but a different taint, so v13.1 surveillance traces do not
    transfer.
    """
    lines = base_source.splitlines()
    out = []
    for ln in lines:
        m = _OPCODE_LINE_RE.match(ln)
        if m and m.group("name") in profile.opcode_map:
            new = f"{m.group(1)}{profile.opcode_map[m.group('name')]:#04x}{m.group(3)}"
            out.append(new)
        else:
            out.append(ln)
    src = "\n".join(out)
    src = _DISC_LINE_RE.sub(
        f"h.update(bytes([_trace_discriminator() ^ {profile.discriminator:#04x}]))",
        src,
    )
    return src


# ---------------------------------------------------------------------------
# Diversified assembler. Mirrors lib/v5/v13/assemble.py but (a) uses the
# per-build opcode byte values, (b) hashes the per-build discriminator
# into the keystream so the emitted byte stream decodes correctly under
# the rendered VM.

import hashlib as _hashlib
from typing import List, Tuple

from . import vm  # only for OP_NOP etc. *names* — we don't use values.


def _snapshot(state):
    out = bytearray(16)
    for i in range(16):
        v = state[i] if i < len(state) else 0
        if isinstance(v, int):
            out[i] = v & 0xFF
        elif isinstance(v, (bytes, bytearray)) and len(v) > 0:
            out[i] = v[0] & 0xFF
    return bytes(out)


def _mask_div(seed: bytes, pc: int, disc: int) -> int:
    h = _hashlib.sha256()
    h.update(seed[:16])
    h.update(pc.to_bytes(4, "big"))
    h.update(bytes([disc]))
    return h.digest()[0]


def _fixed_width(op_name: str) -> int:
    return {
        "NOP": 1, "HLT": 1, "LDI": 3, "LDB": 2, "XAB": 4, "APP": 3,
        "RES": 3, "CL0": 3, "CL1": 4, "MOV": 3, "JMP": 3, "JIFZ": 4,
        "EQ": 4, "ENC": 3, "SCRYPT": 4, "XSTREAM": 4,
    }[op_name]


# Map of canonical vm.OP_* constant values (v13.1 defaults) to their names.
_CANONICAL_BY_VALUE = {
    vm.OP_NOP: "NOP", vm.OP_HLT: "HLT", vm.OP_LDI: "LDI", vm.OP_LDB: "LDB",
    vm.OP_XAB: "XAB", vm.OP_APP: "APP", vm.OP_RES: "RES", vm.OP_CL0: "CL0",
    vm.OP_CL1: "CL1", vm.OP_MOV: "MOV", vm.OP_JMP: "JMP", vm.OP_JIFZ: "JIFZ",
    vm.OP_EQ: "EQ", vm.OP_ENC: "ENC", vm.OP_SCRYPT: "SCRYPT",
    vm.OP_XSTREAM: "XSTREAM",
}


def _resolve_labels(program, name_of_op):
    labels = {}
    pc = 0
    for item in program:
        if isinstance(item, tuple) and len(item) == 2 and item[0] == "LABEL":
            labels[item[1]] = pc
        else:
            op = item[0]
            pc += _fixed_width(name_of_op[op])

    resolved = []
    for item in program:
        if isinstance(item, tuple) and len(item) == 2 and item[0] == "LABEL":
            continue
        op, operands = item
        new_ops = []
        for o in operands:
            if isinstance(o, tuple) and o[0] == "LBL":
                new_ops.append(labels[o[1]])
            else:
                new_ops.append(o)
        resolved.append((op, new_ops))
    return resolved


def assemble_diversified(program, profile: BuildProfile, nstate: int = 64) -> bytes:
    """Assemble `program` against `profile`'s opcode map and keystream
    discriminator. Produces a byte stream that the render_vm_source'd
    VM will decode correctly.
    """
    name_of_op = _CANONICAL_BY_VALUE
    resolved = _resolve_labels(program, name_of_op)

    state = [0] * nstate
    out = bytearray()
    pc = 0

    def emit(byte: int):
        nonlocal pc
        seed = _snapshot(state)
        mask = _mask_div(seed, pc, profile.discriminator)
        out.append((byte ^ mask) & 0xFF)
        pc += 1

    for op_value, operands in resolved:
        name = name_of_op[op_value]
        new_byte = profile.opcode_map[name]
        emit(new_byte)

        if name in ("NOP", "HLT"):
            pass
        elif name == "LDI":
            reg, imm = operands
            emit(reg); emit(imm)
            state[reg] = imm
        elif name == "LDB":
            reg, = operands
            emit(reg)
            state[reg] = bytearray()
        elif name == "XAB":
            dst, a, b = operands
            emit(dst); emit(a); emit(b)
            ba = state[dst]
            va = state[a] if isinstance(state[a], int) else 0
            vb = state[b] if isinstance(state[b], int) else 0
            if isinstance(ba, bytearray):
                ba.append((va ^ vb) & 0xFF)
        elif name == "APP":
            dst, src = operands
            emit(dst); emit(src)
            if isinstance(state[dst], bytearray) and isinstance(state[src], (bytes, bytearray)):
                state[dst].extend(state[src])
        elif name == "RES":
            dst, nm = operands
            emit(dst); emit(nm)
            state[dst] = b""
        elif name == "CL0":
            dst, fn = operands
            emit(dst); emit(fn)
            state[dst] = b""
        elif name == "CL1":
            dst, fn, arg = operands
            emit(dst); emit(fn); emit(arg)
            state[dst] = b""
        elif name == "MOV":
            dst, src = operands
            emit(dst); emit(src)
            state[dst] = state[src]
        elif name == "JMP":
            tgt, = operands
            emit((tgt >> 8) & 0xFF); emit(tgt & 0xFF)
        elif name == "JIFZ":
            reg, tgt = operands
            emit(reg); emit((tgt >> 8) & 0xFF); emit(tgt & 0xFF)
        elif name == "EQ":
            dst, a, b = operands
            emit(dst); emit(a); emit(b)
            state[dst] = 0
        elif name == "ENC":
            dst, src = operands
            emit(dst); emit(src)
            state[dst] = b""
        elif name == "SCRYPT":
            dst, pw, salt = operands
            emit(dst); emit(pw); emit(salt)
            state[dst] = b""
        elif name == "XSTREAM":
            dst, ct, key = operands
            emit(dst); emit(ct); emit(key)
            state[dst] = b""
        else:
            raise ValueError(f"unknown op name: {name}")

    return bytes(out)
