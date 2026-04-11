from functools import reduce

nums = list(range(1, 11))
print(reduce(lambda a, b: a + b, nums))
print(list(map(lambda x: x ** 2, nums)))
print(list(filter(lambda x: x % 2 == 1, nums)))
print(sorted(nums, key=lambda x: -x))
