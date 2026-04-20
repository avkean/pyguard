#!/usr/bin/env python3
"""Measure incremental cost of each obfuscation transform.

Each test = { strip_docstrings | +rename | +string_xor | +dead_code | +cff }
Pipe through minify_py.py afterward to get apples-to-apples source.
"""
import ast
import lzma
import marshal
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, os.path.join(ROOT, 'lib/v5'))

import obfuscate_runtime as obr  # type: ignore
import transform_ast  # type: ignore


def load_src():
    with open(os.path.join(ROOT, 'lib/v5/runtime_interp.py'), 'r') as f:
        s = f.read()
    cut = s.find("# --- self-test entry point")
    if cut >= 0:
        s = s[:cut].rstrip() + '\n'
    return s


def minify(src):
    return subprocess.check_output(
        [sys.executable, os.path.join(ROOT, 'scripts/minify_py.py')],
        input=src, text=True,
    )


def mm(src, label):
    code = compile(src, '<pg_interp>', 'exec', optimize=2)
    m = marshal.dumps(code)
    lz = lzma.compress(m, preset=9 | lzma.PRESET_EXTREME)
    print(f"  {label:50s}  src={len(src):>7} marshal={len(m):>7} lzma={len(lz):>7}")


raw = load_src()


def variant(with_strip=False, with_cff=False, with_rename=False,
            with_stringenc=False, with_dead=False, with_bootkey=False):
    tree = ast.parse(raw)
    if with_strip:
        obr.strip_docstrings(tree)
    if with_cff:
        tree = transform_ast.transform_ast_tree(
            tree, None, rename_identifiers=False,
            rewrite_secret_gates=False, obfuscate_strings=False,
            int_obfuscation=False,
        )
        ast.fix_missing_locations(tree)
    rename_map = None
    if with_rename:
        rename_map = obr.build_rename_map(tree)
        class_methods = obr.collect_class_method_names(tree)
        renamer = obr.IdentifierRenamer(rename_map, class_methods)
        tree = renamer.visit(tree)
    if with_stringenc:
        encoder = obr.StringEncoder()
        tree = encoder.visit(tree)
        decode_nodes = obr._make_xor_decode_func(
            used_names=set(rename_map.values()) if rename_map else set(),
        )
        insert_pos = 0
        for i, stmt in enumerate(tree.body):
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                insert_pos = i + 1
        for j, node in enumerate(decode_nodes):
            tree.body.insert(insert_pos + j, node)
    if with_dead:
        obr.insert_dead_code(tree, n_funcs=4, n_methods_per_class=1)
    if with_bootkey and rename_map:
        reg = obr.make_globals_registration(rename_map)
        tree.body.extend(reg)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


# Full reset
import random

def do(label, **kw):
    random.seed(42)  # reproducible per test
    obr._dead_code_name_counter = 0
    obr._namegen = obr.NameGenerator()
    obr._XOR_DECODE_FUNC_NAME = '_' + ''.join(random.choices(obr._BODY_CHARS, k=8))
    try:
        src = variant(**kw)
        src = minify(src)
        mm(src, label)
    except Exception as e:
        print(f"  {label:50s}  ERROR: {e}")


do("0. baseline (minified raw)", with_strip=True)
do("1. +rename (no cff/string/dead/boot)", with_strip=True, with_rename=True)
do("2. +rename +bootkey", with_strip=True, with_rename=True, with_bootkey=True)
do("3. +rename +bootkey +stringenc", with_strip=True, with_rename=True, with_bootkey=True, with_stringenc=True)
do("4. +rename +bootkey +stringenc +dead", with_strip=True, with_rename=True, with_bootkey=True, with_stringenc=True, with_dead=True)
do("5. +rename +bootkey +stringenc +dead +cff (current)", with_strip=True, with_cff=True, with_rename=True, with_bootkey=True, with_stringenc=True, with_dead=True)

# Simulated 5-version lzma
def pgmv_lzma(src, n=5):
    code = compile(src, '<pg_interp>', 'exec', optimize=2)
    m = marshal.dumps(code)
    pgmv = b'PGMV' + bytes([n])
    for i in range(n):
        pgmv += bytes([3, 9 + i]) + len(m).to_bytes(4, 'little') + m
    return len(lzma.compress(pgmv, preset=9 | lzma.PRESET_EXTREME))

print()
for label, kw in [
    ("0. baseline", dict(with_strip=True)),
    ("1. +rename only", dict(with_strip=True, with_rename=True)),
    ("2. +rename +boot", dict(with_strip=True, with_rename=True, with_bootkey=True)),
    ("5. full (current)", dict(with_strip=True, with_cff=True, with_rename=True, with_bootkey=True, with_stringenc=True, with_dead=True)),
]:
    random.seed(42)
    obr._dead_code_name_counter = 0
    obr._namegen = obr.NameGenerator()
    obr._XOR_DECODE_FUNC_NAME = '_' + ''.join(random.choices(obr._BODY_CHARS, k=8))
    src = variant(**kw)
    src = minify(src)
    print(f"  {label:30s} 5-ver PGMV lzma = {pgmv_lzma(src):>7}")
