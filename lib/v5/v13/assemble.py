"""v13 assembler: symbolic instructions → keystream-masked bytes.

Two-pass: (1) compute instruction offsets for label resolution, then
(2) emit masked bytes while simulating state for the keystream.
"""

from __future__ import annotations
import hashlib
from typing import List, Tuple, Union, Dict

from . import vm


# A symbolic instruction is one of:
#   (op, [operand_bytes])
#   ("LABEL", name)
#   (OP_JMP_or_JIFZ, [..., ("LBL", name), ...])
#
# The assembler resolves labels in pass 1 by computing the fixed byte
# width of each instruction, then in pass 2 emits masked bytes.

SymInstr = Tuple


def _fixed_width(op: int) -> int:
    """Total byte width of (opcode + operands) for `op`."""
    if op in (vm.OP_NOP, vm.OP_HLT):
        return 1
    if op == vm.OP_LDI:
        return 3  # op + reg + imm
    if op == vm.OP_LDB:
        return 2  # op + reg
    if op in (vm.OP_XAB, vm.OP_EQ):
        return 4  # op + dst + a + b
    if op in (vm.OP_APP, vm.OP_RES, vm.OP_CL0, vm.OP_MOV, vm.OP_ENC):
        return 3  # op + two regs
    if op == vm.OP_CL1:
        return 4  # op + dst + fn + arg
    if op == vm.OP_JMP:
        return 3  # op + u16
    if op == vm.OP_JIFZ:
        return 4  # op + reg + u16
    if op in (vm.OP_SCRYPT, vm.OP_XSTREAM):
        return 4  # op + dst + a + b
    raise ValueError(f"unknown op {op:#x}")


def _initial_state(nstate: int):
    return [0] * nstate


def _snapshot(state):
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


def _mask(seed: bytes, pc: int) -> int:
    h = hashlib.sha256()
    h.update(seed[:16])
    h.update(pc.to_bytes(4, "big"))
    h.update(bytes([0]))
    return h.digest()[0]


def _resolve_labels(program: List[SymInstr]) -> Tuple[List[SymInstr], Dict[str, int]]:
    """Pass 1: compute byte offset of each labelled position.

    Input: list of instructions where some entries are ("LABEL", name)
    placeholders and some operands are ("LBL", name) references.
    Output: list of instructions with labels stripped and operands
    resolved to absolute u16 offsets.
    """
    labels: Dict[str, int] = {}
    # First, compute label positions.
    pc = 0
    for item in program:
        if isinstance(item, tuple) and len(item) == 2 and item[0] == "LABEL":
            labels[item[1]] = pc
        else:
            op = item[0]
            pc += _fixed_width(op)

    # Now, resolve label operands.
    resolved: List[SymInstr] = []
    for item in program:
        if isinstance(item, tuple) and len(item) == 2 and item[0] == "LABEL":
            continue
        op, operands = item
        new_ops = []
        for o in operands:
            if isinstance(o, tuple) and o[0] == "LBL":
                target = labels[o[1]]
                new_ops.append(target)
            else:
                new_ops.append(o)
        resolved.append((op, new_ops))
    return resolved, labels


def assemble(program: List[SymInstr], nstate: int = 64) -> bytes:
    resolved, _labels = _resolve_labels(program)

    state = _initial_state(nstate)
    out = bytearray()
    pc = 0

    def emit(byte: int):
        nonlocal pc
        seed = _snapshot(state)
        mask = _mask(seed, pc)
        out.append((byte ^ mask) & 0xFF)
        pc += 1

    for op, operands in resolved:
        emit(op)

        if op in (vm.OP_NOP, vm.OP_HLT):
            pass
        elif op == vm.OP_LDI:
            reg, imm = operands
            emit(reg); emit(imm)
            state[reg] = imm
        elif op == vm.OP_LDB:
            reg, = operands
            emit(reg)
            state[reg] = bytearray()
        elif op == vm.OP_XAB:
            dst, a, b = operands
            emit(dst); emit(a); emit(b)
            ba = state[dst]
            va = state[a] if isinstance(state[a], int) else 0
            vb = state[b] if isinstance(state[b], int) else 0
            ba.append((va ^ vb) & 0xFF)
        elif op == vm.OP_APP:
            dst, src = operands
            emit(dst); emit(src)
            if isinstance(state[dst], bytearray):
                if isinstance(state[src], (bytes, bytearray)):
                    state[dst].extend(state[src])
        elif op == vm.OP_RES:
            dst, name = operands
            emit(dst); emit(name)
            state[dst] = b""  # unknown callable, simulate as non-int
        elif op == vm.OP_CL0:
            dst, fn = operands
            emit(dst); emit(fn)
            state[dst] = b""
        elif op == vm.OP_CL1:
            dst, fn, arg = operands
            emit(dst); emit(fn); emit(arg)
            state[dst] = b""
        elif op == vm.OP_MOV:
            dst, src = operands
            emit(dst); emit(src)
            state[dst] = state[src]
        elif op == vm.OP_JMP:
            tgt, = operands
            emit((tgt >> 8) & 0xFF); emit(tgt & 0xFF)
            # Control flow: simulation continues linearly — the
            # assembler doesn't follow jumps; it lays out code in
            # program order. State after a JMP emission is unchanged
            # from before. This works because the VM state sequence
            # on any real executed path matches the assembler's linear
            # walk, provided labelled forward-jump targets are reached
            # by later emission. For M0 gated programs (straight line
            # through the failure branch then the success branch) this
            # holds.
        elif op == vm.OP_JIFZ:
            reg, tgt = operands
            emit(reg); emit((tgt >> 8) & 0xFF); emit(tgt & 0xFF)
        elif op == vm.OP_EQ:
            dst, a, b = operands
            emit(dst); emit(a); emit(b)
            state[dst] = 0  # sim as 0 to keep deterministic
        elif op == vm.OP_ENC:
            dst, src = operands
            emit(dst); emit(src)
            state[dst] = b""
        elif op == vm.OP_SCRYPT:
            dst, pw, salt = operands
            emit(dst); emit(pw); emit(salt)
            state[dst] = b""  # placeholder — real key computed at runtime
        elif op == vm.OP_XSTREAM:
            dst, ct, key = operands
            emit(dst); emit(ct); emit(key)
            state[dst] = b""
        else:
            raise ValueError(f"unknown opcode {op:#x}")

    return bytes(out)
