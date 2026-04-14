"""Attack 4: Intercept stage2 by patching compile() at C level using ctypes.

The idea: we can't monkey-patch compile() because the stub checks identity.
But we can use code object manipulation or bytecode patching to capture
the decrypted stage2 string _uxprAoICEPr before it's compiled.

Alternative approach: Rather than hooking, let's patch the actual stub code
at the bytecode level to print the decrypted string instead of executing it.
"""
import sys
import os
import types
import dis

# Read the obfuscated file
with open("/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py", "r") as f:
    source = f.read()

# Compile it
code = compile(source, "/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py", "exec")

# Let's examine the code object's constants to understand the structure
print("=== Top-level code constants ===")
for i, c in enumerate(code.co_consts):
    if isinstance(c, types.CodeType):
        print(f"  [{i}] <code {c.co_name}> at line {c.co_firstlineno}")
    elif isinstance(c, bytes):
        print(f"  [{i}] bytes({len(c)}): {c[:20]}...")
    elif isinstance(c, str) and len(c) > 50:
        print(f"  [{i}] str({len(c)}): {c[:50]}...")
    else:
        print(f"  [{i}] {type(c).__name__}: {repr(c)[:80]}")

print(f"\n=== Top-level names: {code.co_names}")
print(f"=== Top-level varnames: {code.co_varnames}")
