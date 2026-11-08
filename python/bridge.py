"""Read CSI from the XIAO (serial) or a saved log, turn it into ~1-second feature
windows, save them as JSON lines, and optionally POST each one to a backend.

Examples:
  python bridge.py --port COM5 --label baseline --checkpoint C1
  python bridge.py --port COM5 --label saltwater --checkpoint C1 --raw data/raw.csv
  python bridge.py --file saved_log.txt
  python bridge.py --port COM5 --url http://localhost:8000/ingest

--raw writes one CSV row per packet: id, ts_us, rssi, label, checkpoint, then the
amplitude of every subcarrier (including the always-zero ones).
Close the idf.py monitor first: only one program can use the COM port.
"""
import argparse
import json
import os
from datetime import datetime, timezone

import numpy as np

from csi_common import packets

WRAP = 2**32  # the board's microsecond clock wraps about every 71 minutes


def send(msg, url):
    """The one place that talks to the backend. Change this once the format is known."""
    if not url:
        return
    try:
        import requests

        requests.post(url, json=msg, timeout=0.5)
    except Exception as e:
        print(f"  send failed: {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--port", help="serial port, e.g. COM5")
    ap.add_argument("--file", help="replay a saved text log instead of using serial")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--window", type=float, default=1.0, help="seconds per window")
    ap.add_argument("--rover-id", default="rover-1")
    ap.add_argument("--checkpoint", default="C0")
    ap.add_argument("--label", default="unlabeled", help="e.g. baseline, saltwater, freshwater")
    ap.add_argument("--out", default="data/windows.jsonl")
    ap.add_argument("--raw", help="optional per-packet CSV, e.g. data/raw.csv")
    ap.add_argument("--url", help="optional backend endpoint to POST each window to")
    args = ap.parse_args()
    if not (args.port or args.file):
        ap.error("give --port COMx (live) or --file log.txt (replay)")

    for path in (args.out, args.raw):
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    out = open(args.out, "a")
    raw = open(args.raw, "a") if args.raw else None

    st = {"mask": None, "ts0": None, "n": 0}
    warm, buf, rssi = [], [], []

    def emit():
        if len(buf) >= 2:
            A = np.stack(buf)[:, st["mask"]].astype(np.float64)
            norm = A / np.maximum(A.mean(axis=1, keepdims=True), 1e-6)
            msg = {
                "rover_id": args.rover_id,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "checkpoint": args.checkpoint,
                "label": args.label,
                "n_packets": len(buf),
                "rssi_mean": round(float(np.mean(rssi)), 2),
                "motion_score": round(float(norm.std(axis=0).mean()), 4),
                "features": {
                    "mean_amp": np.round(A.mean(axis=0), 3).tolist(),
                    "var_amp": np.round(A.var(axis=0), 3).tolist(),
                },
            }
            out.write(json.dumps(msg) + "\n")
            out.flush()
            send(msg, args.url)
            st["n"] += 1
            print(f"window {st['n']}: {msg['n_packets']} pkts, rssi {msg['rssi_mean']}, motion {msg['motion_score']}")
        buf.clear()
        rssi.clear()

    def handle(p):
        if raw:
            row = [str(p["id"]), str(p["ts_us"]), str(p["rssi"]), args.label, args.checkpoint]
            raw.write(",".join(row + [f"{a:.2f}" for a in p["amp"]]) + "\n")
        if st["ts0"] is None:
            st["ts0"] = p["ts_us"]
        if (p["ts_us"] - st["ts0"]) % WRAP >= args.window * 1e6:
            emit()
            st["ts0"] = p["ts_us"]
        buf.append(p["amp"])
        rssi.append(p["rssi"])

    def start_mask():
        # Subcarriers that are always zero (guard band, DC) are dropped automatically
        st["mask"] = np.stack([w["amp"] for w in warm]).max(axis=0) > 0
        for w in warm:
            handle(w)
        warm.clear()

    try:
        for p in packets(args.port, args.baud, args.file):
            if st["mask"] is None:
                warm.append(p)
                if len(warm) >= 50:
                    start_mask()
                continue
            handle(p)
    except KeyboardInterrupt:
        pass
    if st["mask"] is None and warm:
        start_mask()
    emit()
    print(f"done: {st['n']} windows written to {args.out}")


if __name__ == "__main__":
    main()
