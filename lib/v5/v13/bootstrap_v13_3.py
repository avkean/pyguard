"""v13.3 bootstrap template.

Differences from v13.2:

  * The VM runtime is inlined as plaintext (per-build diversified).
    There is no `_VMC` encrypted Python-source blob. This removes
    the `compile()` correctness-oracle that the A24 brute-force
    used: an attacker can no longer reject a wrong password in
    ~microseconds by checking whether the decrypted VM source
    parses.

  * Two ciphertext blobs, chained. `_PA` holds prog_a encrypted
    under scrypt(password, salt). `_PB` holds prog_b encrypted
    under `state_key(state_after_prog_a)`. The attacker cannot
    decrypt _PB without having run prog_a to the correct final
    state, which requires the correct password.

  * No `if exec_failed: emit hex` fallback. The bootstrap writes
    exactly what the VM left in the flag slot (state[16]) plus a
    trailing newline. Right-pass → `FLAG{…}\n`. Wrong-pass → the
    bytes (if any) that garbage opcodes happened to leave in
    state[16], plus `\n`. This is honest about the shape oracle
    rather than cosmetically masking it.

Placeholders substituted by `build_v13_3_stub.py`:

    __VM_SOURCE__      — diversified plaintext VM source (text).
    __SALT__, __NA__, __NB__   — bytes repr.
    __PA__, __PB__             — bytes repr (ciphertexts).
    __N__, __R__, __P__, __DK__  — ints (scrypt params).
    __FLAG_SLOT__              — int (slot where prog_b stores the flag).
    __NSTATE__                 — int (state vector size).
    __MAX_STEPS__              — int (per-stage instruction cap).
"""
from __future__ import annotations


BOOTSTRAP_TEMPLATE = r'''#!/usr/bin/env python3
# PyGuard v13.3 stub. See docs/v13_architecture.md.
import hashlib, sys

_SALT = __SALT__
_NA = __NA__
_NB = __NB__
_PA = __PA__
_PB = __PB__
_N = __N__
_R = __R__
_P = __P__
_DK = __DK__
_FLAG_SLOT = __FLAG_SLOT__
_NSTATE = __NSTATE__
_MAX_STEPS = __MAX_STEPS__
_OUT_LEN = __OUT_LEN__


def _ks(k, n, ln):
    o = bytearray()
    i = 0
    while len(o) < ln:
        h = hashlib.sha256()
        h.update(k); h.update(n); h.update(i.to_bytes(4, "big"))
        o += h.digest()
        i += 1
    return bytes(o[:ln])


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ----- inlined VM (plaintext, per-build diversified) -----
__VM_SOURCE__
# ---------------------------------------------------------


def _main():
    try:
        pw = input().encode("utf-8")
    except EOFError:
        pw = b""
    m = hashlib.scrypt(pw, salt=_SALT, n=_N, r=_R, p=_P, dklen=_DK)

    # v13.3.2: the inner scrypt is computed HERE, unconditionally,
    # every guess. In v13.3.1 it lived inside prog_a as OP_SCRYPT,
    # which on wrong-password garbage prog_a only fired ~2% of the
    # time — so wrong guesses essentially skipped the second scrypt
    # (A30). Moving it to the bootstrap forces both defender and
    # attacker to pay 2x KDF cost every guess. Even if the attacker
    # tries to skip this line, they need state[20] correct to
    # recover the FLAG{ oracle signal on the right password, and
    # state[20] = this scrypt output.
    #
    # v13.3.3 (F4): mix the public _SALT into the pw_in/salt_in
    # derivation. Before, the tag strings `v13_3_2_pa_pw` and
    # `v13_3_2_pa_salt` were build-independent, so two stubs sharing
    # an outer password would share inner = scrypt(f(m), g(m)) as a
    # deterministic function of m only. An attacker who broke one
    # build could reuse the pw_in→inner map against another build.
    # Salting the derivation makes inner build-specific without
    # changing its per-guess cost (one sha256 is negligible next to
    # the scrypt it feeds).
    pw_in = hashlib.sha256(m + _SALT + b"v13_3_3_pa_pw").digest()[:16]
    salt_in = hashlib.sha256(m + _SALT + b"v13_3_3_pa_salt").digest()[:16]
    inner = hashlib.scrypt(pw_in, salt=salt_in, n=_N, r=_R, p=_P, dklen=_DK)

    # v13.3.3 F5: narrow the VM scope to an empty dict. Both prog_a
    # (HLT-only) and prog_b (LDI/LDB/XAB/HLT only) never dispatch
    # OP_RES/OP_CL0/OP_CL1 on the right-pass, so an empty scope is
    # functionally equivalent for correct execution. What changes is
    # wrong-pass behavior: previously, a crafted password whose garbage
    # prog_b happened to decode as OP_RES("eval")+OP_CL1 could pipe
    # attacker-controlled strings through eval() — the curated scope
    # closes that arbitrary-code-execution channel by giving OP_RES
    # nothing to resolve. Right-pass output unchanged.
    _SCOPE: dict = {}

    # Stage A: decrypt prog_a under scrypt-derived master; run it with
    # the inner-scrypt result pre-installed in state[20]. prog_a itself
    # is a no-op now (HLT-only); the state it halts at is identical to
    # init_slots (plus zero elsewhere), which is exactly what state_key
    # needs to compute kb.
    prog_a = _xor(_PA, _ks(m, _NA, len(_PA)))
    state_a = run(prog_a, _SCOPE,
                  nstate=_NSTATE, max_steps=_MAX_STEPS,
                  init_slots={20: inner})

    # Stage B: key_b = sha256(state_key(state_a) || m). state_key
    # length-frames slot 20 = inner = scrypt(f(m), g(m)), so kb
    # depends on the second scrypt unconditionally.
    kb = hashlib.sha256(state_key(state_a) + m).digest()
    prog_b = _xor(_PB, _ks(kb, _NB, len(_PB)))
    state_b = run(prog_b, _SCOPE,
                  nstate=_NSTATE, max_steps=_MAX_STEPS)

    # Output: exactly _OUT_LEN bytes + newline. Unconditional padding
    # path (no `if pad_len > 0:` branch) so wrong-pass and right-pass
    # run byte-identical control flow. Right-pass: first bytes are
    # FLAG (if state[16] is bytearray). Wrong-pass: first bytes are
    # whatever garbage state[16] holds. Same length either way.
    # Content oracle via known FLAG prefix remains — structural
    # property of password gating; v14 target.
    v = state_b[_FLAG_SLOT] if _FLAG_SLOT < len(state_b) else None
    head = bytes(v) if isinstance(v, (bytes, bytearray)) else b""
    pad = state_key(state_b)
    while len(pad) < _OUT_LEN:
        pad += hashlib.sha256(pad).digest()
    out = (head + pad)[:_OUT_LEN]
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    _main()
'''


def render(*, vm_source: str, salt: bytes, nonce_a: bytes, nonce_b: bytes,
           pa_ct: bytes, pb_ct: bytes,
           scrypt_n: int, scrypt_r: int, scrypt_p: int, scrypt_dklen: int,
           flag_slot: int, nstate: int, max_steps: int, out_len: int) -> str:
    subs = {
        "__VM_SOURCE__": vm_source,
        "__SALT__": repr(salt),
        "__NA__": repr(nonce_a),
        "__NB__": repr(nonce_b),
        "__PA__": repr(pa_ct),
        "__PB__": repr(pb_ct),
        "__N__": repr(scrypt_n),
        "__R__": repr(scrypt_r),
        "__P__": repr(scrypt_p),
        "__DK__": repr(scrypt_dklen),
        "__FLAG_SLOT__": repr(flag_slot),
        "__NSTATE__": repr(nstate),
        "__MAX_STEPS__": repr(max_steps),
        "__OUT_LEN__": repr(out_len),
    }
    out = BOOTSTRAP_TEMPLATE
    for k, v in subs.items():
        out = out.replace(k, v)
    return out
