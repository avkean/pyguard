def squares(n):
    for i in range(n):
        yield i * i

evens = [x for x in squares(10) if x % 2 == 0]
print(sum(evens))
print({k: v for k, v in zip("abc", [1, 2, 3])})
