"""Startup file that registers atexit and also wraps sys.exit to ensure it fires."""
import atexit
import gc
import sys
import json
import os

_orig_exit = sys.exit

def _scan():
    gc.collect()
    results = []
    for obj in gc.get_objects():
        try:
            if isinstance(obj, dict) and len(obj) < 500:
                keys = {k for k in obj.keys() if isinstance(k, str)}
                if 'strings' in keys or 'consts' in keys or 'tree' in keys:
                    results.append("IR: " + json.dumps(obj, default=str)[:20000])
                # Look for any dict with integer keys (tag mappings)
                int_keys = {k for k in obj.keys() if isinstance(k, int)}
                if len(int_keys) > 10:
                    vals = list(obj.values())[:5]
                    results.append(f"INTDICT({len(obj)}): keys={sorted(list(int_keys))[:10]}, vals={vals}")
            if isinstance(obj, str) and len(obj) > 100:
                if 'def ' in obj and ('return' in obj or 'print' in obj):
                    results.append(f"SOURCE({len(obj)}): {obj[:5000]}")
                elif 'run_blob' in obj or '_PG_' in obj or 'interp' in obj:
                    results.append(f"INTERP({len(obj)}): {obj[:3000]}")
            if isinstance(obj, list) and 2 < len(obj) < 100:
                if all(isinstance(x, str) for x in obj):
                    # Check for identifier-like strings that could be user code
                    idents = [x for x in obj if x.isidentifier()]
                    if len(idents) > len(obj) * 0.5 and not any(x.startswith('HAVE_') for x in obj[:3]):
                        results.append(f"IDENTLIST({len(obj)}): {obj}")
        except:
            continue

    with open("/Users/avner/Developer/pyguard-master/attack_results2.txt", "w") as f:
        f.write(f"Found {len(results)} items\n\n")
        for r in results:
            f.write(str(r)[:10000] + "\n---\n")

atexit.register(_scan)
