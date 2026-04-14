"""Attack 6: Run the stub as a proper subprocess but use /proc-like inspection.

On macOS we don't have /proc, but we can use lldb/dtrace/ptrace.
Let's try a cleaner approach: use the dis module to understand the code flow
and see if we can extract what we need from the code objects themselves.

Actually, let's try the cleanest attack: run the stub normally but pipe
its stdout, and also try to use sys.addaudithook (if the stub doesn't
block it entirely).
"""
import subprocess
import sys
import os
import tempfile

# First, let's verify the stub runs correctly on its own
result = subprocess.run([sys.executable,
    "/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py"],
    capture_output=True, text=True,
    cwd="/Users/avner/Developer/pyguard-master",
    timeout=10)
print(f"Direct run - stdout: {repr(result.stdout)}, stderr: {repr(result.stderr)}, rc: {result.returncode}")

# Now try using PYTHONSTARTUP to register atexit handler
startup_code = '''
import atexit, gc, sys, json

def _scan():
    gc.collect()
    results = []
    for obj in gc.get_objects():
        try:
            if isinstance(obj, dict) and len(obj) < 200:
                keys = {k for k in obj.keys() if isinstance(k, str)}
                if 'strings' in keys or 'consts' in keys or 'tree' in keys:
                    results.append(json.dumps(obj, default=str)[:10000])
                if any(k.startswith('_PG') for k in keys):
                    results.append(str({k: str(v)[:200] for k, v in obj.items() if isinstance(k, str) and k.startswith('_PG')}))
            if isinstance(obj, str) and len(obj) > 200 and ('def ' in obj or 'class ' in obj or 'import ' in obj):
                results.append(f"SOURCE: {obj[:5000]}")
            if isinstance(obj, list) and 2 < len(obj) < 50:
                if all(isinstance(x, str) for x in obj) and len(obj) > 2:
                    has_user_names = any(len(x) > 1 and x[0] != '_' and x.isidentifier() and x.islower() for x in obj)
                    if has_user_names:
                        results.append(f"NAMES: {obj}")
        except:
            continue
    with open("/Users/avner/Developer/pyguard-master/attack_atexit_results.txt", "w") as f:
        f.write(f"Found {len(results)} items\\n")
        for r in results:
            f.write(r[:5000] + "\\n\\n")

atexit.register(_scan)
'''

# Write startup file
startup_file = "/Users/avner/Developer/pyguard-master/_attack_startup.py"
with open(startup_file, "w") as f:
    f.write(startup_code)

# Run with PYTHONSTARTUP
env = os.environ.copy()
env['PYTHONSTARTUP'] = startup_file

result = subprocess.run([sys.executable,
    "/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py"],
    capture_output=True, text=True,
    cwd="/Users/avner/Developer/pyguard-master",
    env=env, timeout=10)
print(f"PYTHONSTARTUP run - stdout: {repr(result.stdout)}, stderr: {repr(result.stderr)}, rc: {result.returncode}")

# Check if results were written
try:
    with open("/Users/avner/Developer/pyguard-master/attack_atexit_results.txt") as f:
        print(f"Results:\n{f.read()[:5000]}")
except FileNotFoundError:
    print("No results file created")
