"""Attack 7: Use object __del__ finalizer to capture data when the interpreter
cleans up, or use a daemon thread that waits for the main thread to finish.

Actually, better: Use os.register_at_fork or threading.excepthook, or even
simpler - use the -c flag to exec the stub and then scan gc.

Best idea: Use PYTHONSTARTUP to install an atexit handler, but ALSO replace
os._exit with os.exit wrapper that triggers our scan first.

Wait - even simpler. The issue with atexit is that atexit.register() in
PYTHONSTARTUP may be overwritten. Let me check if the stub uses os._exit.

Actually, let me try something different: modify sys.stdout.write to capture
what the interpreter prints AND dump gc objects after detecting output.
No wait - that changes type(print).

Let me try: use a C extension via ctypes to scan memory.
Or even better: just use the debugger (lldb) to attach to the process
and dump memory.

Simplest working approach: Create a wrapper that runs the stub correctly
and then after it finishes scans gc objects. The issue is that the atexit
never fires. Let me figure out why.
"""
import subprocess
import sys
import os

# Check if atexit runs by testing a simpler case
test_code = '''
import atexit
import os

def _at_exit():
    with open("/Users/avner/Developer/pyguard-master/_atexit_test.txt", "w") as f:
        f.write("atexit ran!\\n")

atexit.register(_at_exit)

# Now run the stub
exec(open("/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py").read())
'''

result = subprocess.run([sys.executable, '-c', test_code],
    capture_output=True, text=True,
    cwd="/Users/avner/Developer/pyguard-master",
    timeout=10)
print(f"stdout: {repr(result.stdout)}")
print(f"stderr: {repr(result.stderr[:500])}")
print(f"rc: {result.returncode}")

try:
    with open("/Users/avner/Developer/pyguard-master/_atexit_test.txt") as f:
        print(f"atexit test: {f.read()}")
except:
    print("atexit DID NOT fire")

# Clean up
try: os.unlink("/Users/avner/Developer/pyguard-master/_atexit_test.txt")
except: pass
