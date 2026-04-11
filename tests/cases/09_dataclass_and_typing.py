from dataclasses import dataclass, field
from typing import List

@dataclass
class Point:
    x: float
    y: float
    tags: List[str] = field(default_factory=list)

    def distance_sq(self, other: "Point") -> float:
        return (self.x - other.x) ** 2 + (self.y - other.y) ** 2

p = Point(1.0, 2.0, ["origin"])
q = Point(4.0, 6.0)
print(p.distance_sq(q))
print(p.tags)
