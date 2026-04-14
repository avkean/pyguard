"""PYTHONSTARTUP that registers atexit + intercepts os._exit."""
import atexit
import gc
import sys
import json
import os

# Intercept os._exit to make atexit handlers fire
_real_os_exit = os._exit
def _patched_os_exit(code=0):
    _do_scan()
    _real_os_exit(code)
os._exit = _patched_os_exit

# Also intercept SystemExit
_real_sys_exit = sys.exit
def _patched_sys_exit(code=0):
    _do_scan()
    _real_sys_exit(code)
# Don't patch sys.exit - the stub checks identity

_scan_done = False
def _do_scan():
    global _scan_done
    if _scan_done:
        return
    _scan_done = True
    gc.collect()
    results = []
    for obj in gc.get_objects():
        try:
            if isinstance(obj, dict) and 3 < len(obj) < 500:
                keys = {k for k in obj.keys() if isinstance(k, str)}
                # IR-like structures
                if 'strings' in keys or 'consts' in keys or 'tree' in keys:
                    results.append("IR: " + json.dumps(obj, default=str)[:20000])
                # Namespace dicts with run_blob, _PG_, etc.
                if 'run_blob' in keys:
                    results.append("NS_RUNBLOB: " + str(list(keys)[:30]))
                if any('_PG_' in k for k in keys):
                    results.append("NS_PG: " + str({k: type(v).__name__ for k, v in obj.items() if '_PG_' in str(k)}))
            if isinstance(obj, str) and len(obj) > 50:
                if ('def ' in obj or 'class ' in obj) and 'run_blob' in obj:
                    results.append(f"INTERP_SRC({len(obj)}): {obj[:8000]}")
                elif ('def ' in obj or 'class ' in obj) and len(obj) < 2000:
                    results.append(f"SRC({len(obj)}): {obj[:2000]}")
            if isinstance(obj, bytes) and len(obj) > 50 and len(obj) < 50000:
                try:
                    decoded = obj.decode('utf-8', errors='strict')
                    if 'def ' in decoded or 'class ' in decoded or 'import ' in decoded:
                        results.append(f"BYTES_SRC({len(obj)}): {decoded[:3000]}")
                except:
                    pass
        except:
            continue

    with open("/Users/avner/Developer/pyguard-master/attack_results3.txt", "w") as f:
        f.write(f"Found {len(results)} items\n\n")
        for r in results:
            f.write(str(r)[:10000] + "\n---\n")

atexit.register(_do_scan)
