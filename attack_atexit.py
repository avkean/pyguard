"""Attack 5: Use atexit to scan gc objects after the stub has fully executed.

The stub runs the interpreter which walks the IR tree.
After execution, the IR data structures should still be in memory.
We register an atexit handler BEFORE exec'ing the stub - the stub
clears settrace/setprofile but doesn't clear atexit.
"""
import gc
import sys
import json
import atexit
import types

found_data = []

def scan_gc():
    """Called at process exit - scan all gc objects for IR data."""
    gc.collect()

    for obj in gc.get_objects():
        try:
            if isinstance(obj, dict):
                keys = set(obj.keys()) if len(obj) < 200 else set()
                str_keys = {k for k in keys if isinstance(k, str)}

                # Look for IR tree structure
                if 'tree' in str_keys or 'strings' in str_keys or 'consts' in str_keys:
                    found_data.append(('IR_DICT', json.dumps(obj, default=str)[:10000]))

                # Look for schema data
                if any(k.startswith('_PG') or k.startswith('_S_') for k in str_keys):
                    found_data.append(('SCHEMA', str(dict((k, str(v)[:200]) for k, v in obj.items() if isinstance(k, str) and (k.startswith('_PG') or k.startswith('_S_'))))))

            elif isinstance(obj, list) and 2 < len(obj) < 100:
                # Look for string pools
                if all(isinstance(x, str) for x in obj) and any(x.isidentifier() for x in obj if isinstance(x, str)):
                    found_data.append(('STRING_POOL', obj))

            elif isinstance(obj, str) and len(obj) > 100 and ('def ' in obj or 'import ' in obj or 'class ' in obj):
                # Look for decrypted stage2 source
                found_data.append(('SOURCE_STR', obj[:5000]))

        except Exception:
            continue

    # Write results to a file
    with open("/Users/avner/Developer/pyguard-master/attack_results.txt", "w") as f:
        f.write(f"Found {len(found_data)} items\n\n")
        for kind, data in found_data:
            f.write(f"=== {kind} ===\n")
            if isinstance(data, list):
                f.write(str(data[:50]) + "\n")
            else:
                f.write(str(data)[:5000] + "\n")
            f.write("\n")

    print(f"\n[ATEXIT] Found {len(found_data)} items, wrote to attack_results.txt", file=sys.stderr)

atexit.register(scan_gc)

# Now exec the stub
exec(open("/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py").read())
