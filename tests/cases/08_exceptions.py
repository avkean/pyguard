class MyError(Exception):
    pass

def risky(x):
    if x < 0:
        raise MyError(f"negative: {x}")
    return x * 2

results = []
for v in [1, -2, 3, -4]:
    try:
        results.append(risky(v))
    except MyError as e:
        results.append(str(e))

print(results)
