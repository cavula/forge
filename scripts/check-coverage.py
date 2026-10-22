"""Enforce >=70% statement coverage of implemented business/security helpers."""
import sys
from collections import defaultdict
from pathlib import Path
packages = sys.argv[2:] or ("internal/database", "internal/platform", "internal/testutil")
counts = defaultdict(lambda: [0, 0])
for line in Path(sys.argv[1]).read_text().splitlines()[1:]:
    location, statements, hits = line.split()
    for package in packages:
        if f"/{package}/" in location:
            counts[package][0] += int(statements)
            counts[package][1] += int(statements) if int(hits) else 0
for package in packages:
    total, covered = counts[package]
    ratio = covered / total if total else 0
    print(f"{package}: {ratio:.1%}")
    if ratio < 0.7:
        raise SystemExit(f"{package} must reach 70% coverage")
