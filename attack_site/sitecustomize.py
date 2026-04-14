"""sitecustomize.py - capture ALL compile sources and dump stage2 + interpreter."""
import sys
import os

_compile_sources = []

def _audit_hook(event, args):
    if event == 'compile':
        try:
            src = args[0]
            fname = args[1] if len(args) > 1 else '?'
            if src is not None and isinstance(src, (str, bytes)):
                _compile_sources.append((str(fname), src))
        except:
            pass

try:
    sys.addaudithook(_audit_hook)
except:
    pass

import atexit

def _write_results():
    for i, (fname, src) in enumerate(_compile_sources):
        if isinstance(src, bytes):
            try:
                src = src.decode('utf-8', errors='replace')
            except:
                continue

        # Save each compile source to a separate file
        outpath = f"/Users/avner/Developer/pyguard-master/attack_capture_{i}_{fname.replace('/', '_')}.py"
        with open(outpath, "w") as f:
            f.write(src)

    sys.stderr.write(f"[AUDIT] Saved {len(_compile_sources)} compile sources\n")

atexit.register(_write_results)
