"""Attack: Replay the stage2 source with run_blob hooked to capture IR.

We have the complete stage2 source from the audit hook capture.
We need to provide the correct namespace bindings that stage1 provides:
  _jHrHwBo, _rBRGzjO, _XffgJRddN, _izmiyvUZB, _OWxlVFyRch,
  _jXkpZKOcqty, sys, hashlib, base64, __file__

The key challenge: stage2 also has integrity checks (settrace, setprofile,
compile/exec identity, class name checks, frame depth, audit hooks).

Better approach: Since the audit hook works and doesn't corrupt the key,
let's use it to capture the decrypted+decompressed IR blob directly.
We can hook the exec() call that loads the interpreter and then
replace run_blob in globals before it's called.
"""

# Actually the simplest approach: from the previous scan we know:
# - _0lI1l0 = 4928 (BIN_KEY)
# - _IIOO00 = 698288 (second part of BIN_KEY or noise schedule)
# - _l0llI0 = 9910 (noise schedule value)
# - We have the key mapping, tag mapping, mask, layouts
#
# And from the captured stage2 source:
# - irLabel = bytes([100, 165, 101, 181, 138, 76])
# - _rBRGzjO = bytes.fromhex('9a563cde5c4834bdb0b3cb6125accffc1b4079f5ba7545fa3877e85bd7e358a8')
#
# Let me capture the IR blob by hooking run_blob through the audit mechanism.

import sys
import os

# Create a modified sitecustomize that hooks more aggressively
hook_code = '''
import sys
import os
import json

_ir_blob = None

def _audit_hook(event, args):
    global _ir_blob
    if event == 'compile':
        try:
            src = args[0]
            fname = str(args[1]) if len(args) > 1 else ''
            if isinstance(src, (str, bytes)) and fname == '<string>':
                # This might be the interpreter being compiled
                # After this, run_blob will be available in globals
                pass
        except:
            pass

# Hook globals() access to intercept run_blob
_orig_globals = globals

try:
    sys.addaudithook(_audit_hook)
except:
    pass

import atexit

def _capture():
    import gc
    gc.collect()
    results = []

    # Look for bytes objects that could be the decompressed IR
    for obj in gc.get_objects():
        if isinstance(obj, (bytes, bytearray)):
            if 100 < len(obj) < 50000:
                # Check if it looks like our binary IR format
                # Binary IR starts with a tag byte (l for list, m for map, s for string, etc)
                if len(obj) > 10 and obj[0:1] in (b'l', b'm', b's'):
                    results.append(f"BIN_IR({len(obj)}): {obj[:200].hex()}")
                    # Save the full blob
                    with open(f"/Users/avner/Developer/pyguard-master/attack_ir_blob_{len(obj)}.bin", "wb") as f:
                        f.write(obj)

    with open("/Users/avner/Developer/pyguard-master/attack_ir_blobs.txt", "w") as f:
        f.write(f"Found {len(results)} potential IR blobs\\n")
        for r in results:
            f.write(r + "\\n")
    sys.stderr.write(f"[CAP] {len(results)} potential IR blobs\\n")

atexit.register(_capture)
'''

site_dir = "/Users/avner/Developer/pyguard-master/attack_site"
with open(os.path.join(site_dir, "sitecustomize.py"), "w") as f:
    f.write(hook_code)

import subprocess
result = subprocess.run([sys.executable,
    "/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py"],
    capture_output=True, text=True,
    env={**os.environ, 'PYTHONPATH': site_dir},
    timeout=15)
print(f"stdout: {repr(result.stdout)}")
print(f"stderr: {repr(result.stderr)}")

# Check results
try:
    with open("/Users/avner/Developer/pyguard-master/attack_ir_blobs.txt") as f:
        print(f.read())
except:
    print("No IR blobs file")

# Check for saved blobs
import glob
blobs = glob.glob("/Users/avner/Developer/pyguard-master/attack_ir_blob_*.bin")
print(f"Saved blobs: {blobs}")
