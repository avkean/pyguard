"""Build a v13 KDF-gated stub (M1): unconditional decrypt-and-print.

No client-side verifier. Wrong password → high-entropy garbage.
Right password → flag. The KDF work factor is scrypt.
"""
from __future__ import annotations
import inspect
from pathlib import Path
from . import vm, assemble, kdf_gated_program


STUB_TEMPLATE = '''#!/usr/bin/env python3
# PYGUARD_SECRETS: {PASSWORD}, {FLAG}
# Protected by PyGuard v13 (M1 prototype, KDF-gated).
import builtins, hashlib, sys

{VM_SOURCE}

_PAYLOAD = {PAYLOAD!r}

if __name__ == "__main__":
    run(_PAYLOAD, dict(builtins.__dict__))
'''


def _strip_vm_source() -> str:
    vm_src = inspect.getsource(vm)
    lines = vm_src.splitlines()
    filtered, in_ds = [], False
    for ln in lines:
        if ln.startswith('"""') and not in_ds:
            in_ds = True
            if ln.count('"""') >= 2:
                in_ds = False
            continue
        if in_ds:
            if ln.endswith('"""'):
                in_ds = False
            continue
        if ln.startswith("from __future__"):
            continue
        if ln.startswith("import hashlib") or ln.startswith("import sys"):
            continue
        filtered.append(ln)
    return "\n".join(filtered)


def build(out_path: str | Path):
    prog, meta = kdf_gated_program.build_program_and_meta()
    payload = assemble.assemble(prog)

    vm_src_clean = _strip_vm_source()

    stub = STUB_TEMPLATE.format(
        VM_SOURCE=vm_src_clean,
        PAYLOAD=payload,
        PASSWORD=meta["password"].decode("ascii"),
        FLAG=meta["flag"].decode("ascii"),
    )
    Path(out_path).write_text(stub)
    return out_path, meta


if __name__ == "__main__":
    import sys as _sys
    out = _sys.argv[1] if len(_sys.argv) > 1 else "out_v13_kdf_gated.py"
    path, meta = build(out)
    size = Path(path).stat().st_size
    print(f"wrote {path} ({size} bytes)")
    print(f"  password (plaintext, for testing): {meta['password']!r}")
    print(f"  flag     (plaintext, for testing): {meta['flag']!r}")
    print(f"  salt     (in stub, recoverable):   {meta['salt'].hex()}")
    print(f"  ciphertext (in stub, recoverable): {meta['ciphertext'].hex()}")
