"""How does check() latency grow with the number of tracked values?

    python evals/scaling.py              # 1k, 10k and 40k records (about 12 s)
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from flowguard import Guard, Policy  # noqa: E402

policy = Policy.default(destinations={"trusted_api": "CONFIDENTIAL"})
print("| Records | Tracked values | Registering | check() median | check() max |")
print("|---:|---:|---:|---:|---:|")
for n in (1_000, 10_000, 40_000):
    guard = Guard(policy)
    start = time.perf_counter()
    for i in range(n):
        ssn = f"{100 + i % 800:03d}-{10 + i % 80:02d}-{1000 + i % 9000:04d}"
        guard.observe({"ssn": ssn, "email": f"user{i}@corp.example", "salary": 50000 + i}, source="db")
    registering = time.perf_counter() - start
    latencies = []
    for k in range(30):
        start = time.perf_counter()
        guard.check("trusted_api", f"Weekly status report {k}: all systems nominal, 42 tickets closed.")
        latencies.append((time.perf_counter() - start) * 1000)
    latencies.sort()
    med, worst = latencies[15], latencies[-1]
    row = (f"{n:,}", f"{len(guard.registry):,}", f"{registering:.1f} s", f"{med:.2f} ms", f"{worst:.2f} ms")
    print("| " + " | ".join(row) + " |")
