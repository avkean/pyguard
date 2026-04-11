import json
import os
from collections import Counter

data = {"a": 1, "b": 2, "c": [3, 4, 5]}
s = json.dumps(data, sort_keys=True)
print(s)
print(Counter("mississippi").most_common(2))
print(os.path.basename("/tmp/foo/bar.txt"))
