#!/usr/bin/env python3
"""Summarizes bench result files: first call after the dial ("cold") and the
rest ("warm") per label, pooled over every file given for that label.

Usage: summarize.py [LABEL=]FILE... (files with the same label are pooled;
FILE may be a quoted glob such as 'after=/tmp/after-*.json')
"""
import glob
import json
import statistics
import sys
from collections import OrderedDict


def pct(values, p):
    s = sorted(values)
    return s[min(len(s) - 1, int(p * len(s)))]


def main():
    groups = OrderedDict()
    for arg in sys.argv[1:]:
        label, _, pattern = arg.rpartition("=")
        paths = sorted(glob.glob(pattern)) or [pattern]
        groups.setdefault(label or pattern, []).extend(paths)
    for label, paths in groups.items():
        cold, warm, errors = [], [], 0  # errors: failed calls and failed dials
        for path in paths:
            with open(path) as f:
                res = json.load(f)["res"]
            calls = res["calls"]
            errors += len(res.get("dialErrors", []))
            done = [c["done"] for c in calls if "done" in c]
            errors += sum(1 for c in calls if "err" in c)
            if done:
                cold.append(done[0])
                warm.extend(done[1:])
        if not warm:
            print(f"{label}: no completed calls ({errors} errors)")
            continue
        print(
            f"{label}: runs {len(paths)} warm n {len(warm)} p50 {statistics.median(warm):.0f} "
            f"p90 {pct(warm, 0.9):.0f} mean {statistics.mean(warm):.0f} max {max(warm):.0f} | "
            f"cold p50 {statistics.median(cold):.0f} mean {statistics.mean(cold):.0f} | errors {errors}"
        )


if __name__ == "__main__":
    main()
