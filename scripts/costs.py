#!/usr/bin/env python3
"""Roll up what the trajectories say model calls cost (#190).

    scripts/costs.py                 # today, every channel
    scripts/costs.py --days 7        # the last 7 days
    scripts/costs.py --channel C123  # one channel

Reads the trajectory JSONL the agent already writes -- no new store, and
nothing here talks to a vendor. Unpriced calls are counted and reported
separately rather than folded in as zero: a subscription rung and a model
missing from LiteLLM's cost map both produce no number, and a rollup that
shows those as free is wrong in the one direction nobody checks.
"""
import argparse
import collections
import datetime
import glob
import json
import os
import sys

DIR = os.getenv("SHMOBSTER_TRAJECTORIES", "trajectories")


def records(days, channel=None):
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=days - 1)).strftime("%Y-%m-%d")
    pattern = os.path.join(DIR, channel or "*", "*.jsonl")
    for path in sorted(glob.glob(pattern)):
        day = os.path.basename(path)[:10]
        if day < cutoff:
            continue
        chan = os.path.basename(os.path.dirname(path))
        try:
            with open(path) as f:
                for line in f:
                    try:
                        yield day, chan, json.loads(line)
                    except ValueError:
                        continue
        except OSError as exc:
            print(f"warning: {path}: {exc}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=1, help="how many days back (default 1: today)")
    ap.add_argument("--channel", help="one channel id; default every channel")
    args = ap.parse_args()

    by_chan = collections.defaultdict(lambda: [0.0, 0, 0, 0])   # cost, priced, unpriced, turns
    by_vendor = collections.defaultdict(lambda: [0.0, 0, 0])
    by_day = collections.defaultdict(lambda: [0.0, 0, 0])
    for day, chan, rec in records(args.days, args.channel):
        calls = rec.get("calls")
        if not isinstance(calls, list):
            continue  # recorded before costs existed; not the same as "free"
        by_chan[chan][3] += 1
        for c in calls:
            if not isinstance(c, dict):
                continue
            v = c.get("cost")
            # A cost that is not a number is not a cost. Coercing a string here
            # would turn type drift into a total nobody could audit; counting
            # it unpriced says "we do not know", which is true.
            if isinstance(v, bool):
                v = None
            priced = isinstance(v, (int, float))
            amount = float(v) if priced else 0.0
            for bucket in (by_chan[chan], by_vendor[c.get("vendor") or "unknown"], by_day[day]):
                bucket[0] += amount
                bucket[1 if priced else 2] += 1

    if not by_chan:
        print("no cost records in range "
              f"({DIR}, {args.days} day(s)). Turns recorded before #190 carry no calls.")
        return 0

    def rows(title, data, extra=None):
        print(f"\n{title}")
        for key in sorted(data, key=lambda k: -data[k][0]):
            cost, priced, unpriced = data[key][0], data[key][1], data[key][2]
            line = f"  {key:<24} ${cost:>9.4f}  {priced:>4} priced  {unpriced:>4} unpriced"
            if extra:
                line += f"  {data[key][3]:>4} turns"
            print(line)

    rows(f"By channel ({args.days} day(s))", by_chan, extra=True)
    rows("By vendor", by_vendor)
    rows("By day", by_day)
    total = sum(v[0] for v in by_chan.values())
    unpriced = sum(v[2] for v in by_chan.values())
    print(f"\nTotal ${total:.4f}"
          + (f", plus {unpriced} unpriced call(s) -- the real total is higher" if unpriced else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
