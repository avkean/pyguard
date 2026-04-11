class Counter:
    def __init__(self, start=0):
        self.value = start

    def inc(self, n=1):
        self.value += n
        return self

    def get(self):
        return self.value


c = Counter(10)
c.inc().inc(5).inc()
print(c.get())
