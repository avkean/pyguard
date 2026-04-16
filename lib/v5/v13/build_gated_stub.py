"""Build a v13 gated stub (password check → flag)."""
from __future__ import annotations
import inspect
from pathlib import Path
from . import vm, assemble, gated_program


STUB_TEMPLATE = '''#!/usr/bin/env python3
# PYGUARD_SECRETS: correcthorse, FLAG{{v13_m0_gated_local_check}}
# Protected by PyGuard v13 (M0 prototype, gated test case).
import builtins, hashlib, sys

{VM_SOURCE}

_PAYLOAD = {PAYLOAD!r}

if __name__ == "__main__":
    run(_PAYLOAD, dict(builtins.__dict__))
'''


def build(out_path: str | Path):
    prog = gated_program.build_program()
    payload = assemble.assemble(prog)

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
    vm_src_clean = "\n".join(filtered)

    stub = STUB_TEMPLATE.format(VM_SOURCE=vm_src_clean, PAYLOAD=payload)
    Path(out_path).write_text(stub)
    return out_path


if __name__ == "__main__":
    import sys as _sys
    out = _sys.argv[1] if len(_sys.argv) > 1 else "out_v13_gated.py"
    path = build(out)
    print(f"wrote {path} ({Path(path).stat().st_size} bytes)")
