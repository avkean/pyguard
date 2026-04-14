"""Attack 2: Use signal handler to inspect frames during execution."""
import gc
import sys
import json
import signal
import os

# Strategy: Use SIGALRM to interrupt execution at various points
# and inspect the frame stack for decrypted IR data

collected = []

def alarm_handler(signum, frame):
    """Walk all frames and collect interesting locals/globals."""
    f = frame
    depth = 0
    while f is not None:
        for name, val in list(f.f_locals.items()):
            if isinstance(val, dict):
                keys = set(val.keys()) if len(val) < 100 else set()
                if 'strings' in keys or 'consts' in keys or 'tree' in keys:
                    try:
                        collected.append(('frame_dict', name, json.dumps(val, default=str)[:5000]))
                    except:
                        collected.append(('frame_dict', name, str(val)[:5000]))
            if isinstance(val, list) and len(val) > 0 and len(val) < 50:
                if all(isinstance(x, str) for x in val):
                    collected.append(('string_list', name, val))
        f = f.f_back
        depth += 1
    # Re-arm the alarm
    signal.setitimer(signal.ITIMER_REAL, 0.001)

# Set up SIGALRM handler
signal.signal(signal.SIGALRM, alarm_handler)

# Start firing alarms every 1ms
signal.setitimer(signal.ITIMER_REAL, 0.001, 0.001)

try:
    exec(open("/Users/avner/Developer/pyguard-master/tests/out_v5/02_function_calls_function.py").read())
except SystemExit:
    pass
except Exception as e:
    print(f"Error: {e}")

# Stop alarms
signal.setitimer(signal.ITIMER_REAL, 0)

print(f"\nCollected {len(collected)} items")
for kind, name, val in collected[:30]:
    print(f"\n{kind}: {name}")
    if isinstance(val, str):
        print(val[:500])
    else:
        print(val)
