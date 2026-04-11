import asyncio

async def fetch(name, delay):
    await asyncio.sleep(delay)
    return f"{name}-done"

async def main():
    results = await asyncio.gather(
        fetch("a", 0.01),
        fetch("b", 0.005),
        fetch("c", 0.002),
    )
    print(sorted(results))

asyncio.run(main())
