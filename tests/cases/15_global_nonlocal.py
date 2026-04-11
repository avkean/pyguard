counter = 0

def bump():
    global counter
    counter += 1

def make_acc():
    total = 0
    def acc(x):
        nonlocal total
        total += x
        return total
    return acc

a = make_acc()
print(a(5), a(10), a(7))
for _ in range(3):
    bump()
print(counter)
