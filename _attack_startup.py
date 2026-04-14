
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
        f.write(f"Found {len(results)} items\n")
        for r in results:
            f.write(r[:5000] + "\n\n")

atexit.register(_scan)
