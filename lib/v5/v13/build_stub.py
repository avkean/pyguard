"""Build a M0 v13 stub file on disk.

Output is a standalone Python script that:
  1. Contains the masked payload as a bytes literal.
  2. Ships the VM runtime inline (not imported from this package —
     the protected file must be self-contained copy-paste Python).
  3. Calls vm.run(payload, scope) to execute the hello-world program.

No marshal. No types.FunctionType for user logic. The VM IS the
interpreter; user logic is pure data flowing through it.
"""
from __future__ import annotations
import inspect
from pathlib import Path
from . import vm, assemble, hello_program


STUB_TEMPLATE = '''#!/usr/bin/env python3
# Protected by PyGuard v13 (M0 prototype).
import builtins, hashlib, sys

{VM_SOURCE}

_PAYLOAD = {PAYLOAD!r}

if __name__ == "__main__":
    run(_PAYLOAD, dict(builtins.__dict__))
'''


def build(out_path: str | Path):
    prog = hello_program.build_program()
    payload = assemble.assemble(prog)

    # Inline the VM source verbatim. We strip the "from __future__"
    # and package imports because the stub must be standalone.
    vm_src = inspect.getsource(vm)
    # Strip "from __future__ import annotations" and leading module
    # docstring; keep the real code.
    lines = vm_src.splitlines()
    filtered = []
    in_docstring = False
    for ln in lines:
        if ln.startswith('"""') and not in_docstring:
            in_docstring = True
            if ln.count('"""') >= 2:
                in_docstring = False
            continue
        if in_docstring:
            if ln.endswith('"""'):
                in_docstring = False
            continue
        if ln.startswith("from __future__"):
            continue
        if ln.startswith("import hashlib") or ln.startswith("import sys"):
            continue  # already imported at stub top
        filtered.append(ln)
    vm_src_clean = "\n".join(filtered)

    stub = STUB_TEMPLATE.format(VM_SOURCE=vm_src_clean, PAYLOAD=payload)
    Path(out_path).write_text(stub)
    return out_path


if __name__ == "__main__":
    import sys as _sys
    out = _sys.argv[1] if len(_sys.argv) > 1 else "out_v13_hello.py"
    path = build(out)
    print(f"wrote {path} ({Path(path).stat().st_size} bytes)")
