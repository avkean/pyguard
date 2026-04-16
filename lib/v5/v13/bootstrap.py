"""v13.2 stage-0 bootstrap template.

The bootstrap is the ONLY plaintext code in a v13.2 stub. It is
kept as small as the design allows:

  * No references to the word "scrypt" or "FLAG" or any semantic
    string from the inner program. Literal "hashlib.scrypt" would
    be a billboard for attack tooling; a v13.3 pass will replace it
    with primitives that compute scrypt without containing the name.
  * No inline parameter values that would let a reader identify
    the KDF by eye beyond what hashlib itself exposes.
  * All error paths produce deterministic pseudo-random hex output
    of fixed length so wrong-password runs look structurally like
    right-password runs modulo the final bytes. No stderr leaks,
    no exception message, no timing anomaly beyond the scrypt cost
    itself.

The output protocol: the bootstrap's stdout is
    raw_bytes_from_exec  ||  \"\\n\"  (if exec produced output)
or
    sha256(master || nonce_vm).hex() || \"\\n\"   (if exec produced nothing)

Both paths write exactly one trailing newline. Both paths go through
`sys.stdout.buffer.write` to avoid codec issues on non-UTF-8 bytes.
"""
from __future__ import annotations

# Placeholders are substituted by build_v13_2_stub. Each placeholder is
# a Python-repr'd value so the result is valid Python. Literal braces
# in the template are escaped as {{ }}.
BOOTSTRAP_TEMPLATE = r'''#!/usr/bin/env python3
# PyGuard v13.2 stub. See docs/v13_architecture.md.
import builtins, contextlib, hashlib, io, sys

_SALT = __SALT__
_NVM = __NVM__
_NPR = __NPR__
_VMC = __VMC__
_PRC = __PRC__
_N = __N__
_R = __R__
_P = __P__
_DK = __DK__


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


def _main():
    try:
        pw = input().encode("utf-8")
    except EOFError:
        pw = b""
    m = hashlib.scrypt(pw, salt=_SALT, n=_N, r=_R, p=_P, dklen=_DK)
    vm_src = _xor(_VMC, _ks(m, _NVM, len(_VMC)))
    prog   = _xor(_PRC, _ks(m, _NPR, len(_PRC)))

    buf_out = io.BytesIO()
    buf_err = io.StringIO()

    class _W:
        def __init__(self, under): self._u = under
        def write(self, s):
            if isinstance(s, str):
                self._u.write(s.encode("utf-8", errors="surrogateescape"))
            else:
                self._u.write(s)
            return len(s) if hasattr(s, "__len__") else 0
        def flush(self): pass
        @property
        def buffer(self): return self._u

    wrapped = _W(buf_out)
    ok = False
    try:
        with contextlib.redirect_stdout(wrapped), contextlib.redirect_stderr(buf_err):
            ns = {"__builtins__": builtins}
            exec(vm_src.decode("utf-8", errors="surrogateescape"), ns)
            if "run" in ns:
                ns["run"](prog, dict(builtins.__dict__))
        ok = True
    except BaseException:
        ok = False

    data = buf_out.getvalue()
    if not ok or not data:
        data = hashlib.sha256(m + _NVM + _NPR).hexdigest().encode("ascii")
    sys.stdout.buffer.write(data)
    if not data.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    _main()
'''


def render(*, salt: bytes, nonce_vm: bytes, nonce_prog: bytes,
           vm_ct: bytes, prog_ct: bytes,
           scrypt_n: int, scrypt_r: int, scrypt_p: int, scrypt_dklen: int) -> str:
    subs = {
        "__SALT__": repr(salt),
        "__NVM__": repr(nonce_vm),
        "__NPR__": repr(nonce_prog),
        "__VMC__": repr(vm_ct),
        "__PRC__": repr(prog_ct),
        "__N__": repr(scrypt_n),
        "__R__": repr(scrypt_r),
        "__P__": repr(scrypt_p),
        "__DK__": repr(scrypt_dklen),
    }
    out = BOOTSTRAP_TEMPLATE
    for k, v in subs.items():
        out = out.replace(k, v)
    return out
