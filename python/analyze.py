"""Does CSI actually separate your conditions? Compares every label against a reference
label (default: baseline).

  python analyze.py dataset/<session>/windows.jsonl     (from collect.py)
  python analyze.py data/raw.csv --window 200           (from bridge.py --raw)

Three features per window:
  rssi   average RSSI (overall signal strength; saltwater absorption could show here)
  level  average raw CSI amplitude (overall level)
  shape  how far the window's normalized subcarrier pattern is from the reference's
d is Cohen's d versus the reference: |d| >= 2 is clearly separable, 1 to 2 is weak,
under 1 is lost in the noise. Windows from one run are correlated, so d is optimistic;
the honest test is the held-out split="test" round. Keep a second baseline (a label like
baseline_b recorded later) to measure drift: a real effect must beat baseline vs baseline_b.
"""
import argparse
import collections
import csv
import json

import matplotlib.pyplot as plt
import numpy as np

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
ap.add_argument("data")
ap.add_argument("--ref", default="baseline")
ap.add_argument("--window", type=int, default=200, help="packets per window (raw.csv only)")
args = ap.parse_args()

feats = {}
if args.data.endswith(".jsonl"):
    by = collections.defaultdict(list)
    with open(args.data) as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                by[rec["label"]].append(rec)
    for lab, v in by.items():
        if len(v) >= 2:
            feats[lab] = {"rssi": np.array([x["rssi_mean"] for x in v]),
                          "level": np.array([x["level"] for x in v]),
                          "spec": np.array([x["shape"] for x in v])}
    note = "1-second windows from collect.py"
else:
    amps, rssis, width = collections.defaultdict(list), collections.defaultdict(list), None
    with open(args.data, newline="") as f:
        for row in csv.reader(f):
            try:
                a, rs = np.array(row[5:], dtype=float), float(row[2])
            except (ValueError, IndexError):
                continue
            width = width or len(a)
            if len(a) == width:
                amps[row[3]].append(a)
                rssis[row[3]].append(rs)
    if amps:
        mask = np.vstack([a for v in amps.values() for a in v]).max(axis=0) > 0
    W = args.window
    for lab in amps:
        A, R = np.stack(amps[lab])[:, mask], np.array(rssis[lab])
        n = len(A) // W
        if n < 2:
            print(f"{lab}: {len(A)} packets is under two windows of {W}; skipped")
            continue
        A, R = A[: n * W].reshape(n, W, -1), R[: n * W].reshape(n, W)
        feats[lab] = {"rssi": R.mean(axis=1), "level": A.mean(axis=(1, 2)),
                      "spec": (A / np.maximum(A.mean(axis=2, keepdims=True), 1e-6)).mean(axis=1)}
    note = f"windows of {W} packets from bridge.py --raw"

if args.ref not in feats:
    raise SystemExit(f"Not enough data labelled '{args.ref}'. Labels with 2+ windows: {list(feats)}")

ref = feats[args.ref]["spec"]
m = len(ref)
for lab, d in feats.items():
    if lab == args.ref:   # leave-one-out so the baseline isn't compared with itself
        d["shape"] = np.array([np.sqrt(np.mean((ref[i] - (ref.sum(0) - ref[i]) / (m - 1)) ** 2)) for i in range(m)])
    else:
        d["shape"] = np.sqrt(np.mean((d["spec"] - ref.mean(0)) ** 2, axis=1))


def cohen(x, y):
    sp = np.sqrt(((len(x) - 1) * x.var(ddof=1) + (len(y) - 1) * y.var(ddof=1)) / (len(x) + len(y) - 2))
    return (y.mean() - x.mean()) / sp if sp > 0 else float("nan")


print(f"\n{note}; reference = '{args.ref}'\n")
print(f"{'label':<18}{'wins':>5}  {'rssi (d)':>16}  {'level (d)':>16}  {'shape (d)':>16}  verdict")
for lab, d in feats.items():
    cells, best = [], 0.0
    for k in ("rssi", "level", "shape"):
        if lab == args.ref:
            cells.append(f"{d[k].mean():8.2f}      ref")
        else:
            e = cohen(feats[args.ref][k], d[k])
            best = max(best, abs(e)) if e == e else best
            cells.append(f"{d[k].mean():8.2f} ({e:+5.1f})")
    verdict = "" if lab == args.ref else ("clearly separable" if best >= 2 else "weak" if best >= 1 else "not separable")
    print(f"{lab:<18}{len(d['rssi']):>5}  {cells[0]:>16}  {cells[1]:>16}  {cells[2]:>16}  {verdict}")

fig, axes = plt.subplots(1, 3, figsize=(13, 4))
for ax, k in zip(axes, ("rssi", "level", "shape")):
    ax.boxplot([d[k] for d in feats.values()], tick_labels=list(feats))
    ax.set_title(k)
    ax.tick_params(axis="x", rotation=30)
plt.tight_layout()
plt.savefig("analysis.png", dpi=120)
print("\nSaved analysis.png")
plt.show()
