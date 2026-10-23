"""Enforce >=70% statement coverage of implemented business/security helpers."""
import sys
from collections import defaultdict
from pathlib import Path
counts = defaultdict(lambda: [0, 0])
packages = sorted({str(p.parent) for p in Path("internal").rglob("*.go")
                   if not p.name.endswith("_test.go")})
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
