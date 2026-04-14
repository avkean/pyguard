"""Attack 1: Use gc.get_objects() to find IR data structures after execution."""
import gc
import sys
import json

# We'll run the obfuscated file and then inspect gc objects
# First, let's try running it in a subprocess and using gc

import subprocess
result = subprocess.run([sys.executable, '-c', '''
import gc
import sys
import json

# Enable gc tracking
gc.set_debug(0)

# Run the obfuscated file
exec(open("tests/out_v5/02_function_calls_function.py").read())

# Now search gc objects for IR-like dicts
found = []
for obj in gc.get_objects():
    if isinstance(obj, dict):
        keys = set(obj.keys())
        # Look for IR-related structures
        if 'strings' in keys or 'consts' in keys or 'tree' in keys:
            try:
                found.append(json.dumps(obj, default=str)[:2000])
            except:
                found.append(str(obj)[:2000])
        # Look for schema-related
        if any(k.startswith('_PG_') or k.startswith('_S_') for k in keys if isinstance(k, str)):
            try:
                found.append(json.dumps(obj, default=str)[:2000])
            except:
                found.append(str(obj)[:2000])

print("FOUND_ITEMS:", len(found))
for f in found[:20]:
    print("ITEM:", f[:500])
'''], capture_output=True, text=True, cwd='/Users/avner/Developer/pyguard-master')

print("STDOUT:", result.stdout[:3000])
print("STDERR:", result.stderr[:3000])
