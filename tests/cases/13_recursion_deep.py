def sum_to(n, acc=0):
    if n == 0:
        return acc
    return sum_to(n - 1, acc + n)

print(sum_to(500))
