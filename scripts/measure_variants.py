#!/usr/bin/env python3
"""Measure interpreter-source size variants and resulting marshal sizes.

Inputs we compare:
  A. Raw runtime_interp.py (self-test block stripped)
  B. Minified only (no obfuscate_runtime.py)
  C. Current pipeline (obfuscate_runtime.py + minify_py.py)

For each, we compile+marshal on python3.11 (the largest case) and report
lzma-compressed bytes. Focuses on interpreter only -- the biggest cost.
"""
import lzma
import marshal
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(ROOT, 'lib/v5/runtime_interp.py'), 'r') as f:
    raw = f.read()
cut_marker = "# --- self-test entry point"
cut = raw.find(cut_marker)
if cut >= 0:
    raw = raw[:cut].rstrip() + '\n'


def mm(src, label):
    code = compile(src, '<pg_interp>', 'exec', optimize=2)
    m = marshal.dumps(code)
    lz = lzma.compress(m, preset=9 | lzma.PRESET_EXTREME)
    print(f"  {label:35s}  src={len(src):>7} marshal={len(m):>7} lzma={len(lz):>7}")


print("# raw self-test-stripped source")
mm(raw, "A. raw (no obfuscation)")

print("# minified only")
minified = subprocess.check_output(
    [sys.executable, os.path.join(ROOT, 'scripts/minify_py.py')],
    input=raw, text=True,
)
mm(minified, "B. minify only (no obfuscate)")

print("# full current pipeline")
obfuscated = subprocess.check_output(
    [sys.executable, os.path.join(ROOT, 'scripts/obfuscate_runtime.py')],
    text=True,
)
mm(obfuscated, "C1. obfuscate (raw)")
c_minified = subprocess.check_output(
    [sys.executable, os.path.join(ROOT, 'scripts/minify_py.py')],
    input=obfuscated, text=True,
)
mm(c_minified, "C2. obfuscate + minify (current)")

# For multi-version test, simulate 5-version PGMV + lzma
def pgmv_lzma(src, n=5):
    code = compile(src, '<pg_interp>', 'exec', optimize=2)
    m = marshal.dumps(code)
    # Simulate 5 version entries (same bytes — simulates best-case LZMA dedup;
    # real multi-version varies slightly so lzma gain is realistic lower bound)
    pgmv = b'PGMV' + bytes([n])
    for i in range(n):
        pgmv += bytes([3, 9 + i]) + len(m).to_bytes(4, 'little') + m
    return len(lzma.compress(pgmv, preset=9 | lzma.PRESET_EXTREME))

print("\n# simulated 5-version PGMV lzma")
print(f"  A (raw):     {pgmv_lzma(raw)}")
print(f"  B (minify):  {pgmv_lzma(minified)}")
print(f"  C (current): {pgmv_lzma(c_minified)}")
