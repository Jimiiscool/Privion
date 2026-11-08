"""Guided data collection for training the model.

Walks you through a list of conditions (baseline, saltwater, ...), records each one for
a fixed time, and writes a tidy dataset folder:

  dataset/<session>/windows.jsonl  one record per ~1 s window: labels + features   <- this goes to the backend
  dataset/<session>/raw.csv        one row per packet (active subcarriers only)
  dataset/<session>/meta.json      setup, subcarrier indices, field descriptions, run list

  python collect.py --port COM5 --labels baseline,saltwater,saltwater_shake --rounds 3 --seconds 45
  python collect.py --port COM5 --note "tray 30x20 cm on the line of sight, 1 m apart"
  python collect.py --file saved_log.txt --labels baseline,saltwater --rounds 2   (replay, no prompts)

Every run (one label, one round) has its own run_id. The last round is marked
split="test" so the model is judged on data it never trained on. Label order is shuffled
inside each round so slow drift can't pose as a real effect.
Close the idf.py monitor first: only one program can use the COM port.
"""
import argparse
import csv
import json
import os
import queue
import random
import threading
import time
from datetime import datetime, timezone

import numpy as np

from csi_common import packets

WRAP = 2**32  # the board's microsecond clock wraps about every 71 minutes

SCHEMA = {
    "run_id": "one continuous recording of one label",
    "label": "condition being recorded, e.g. baseline / saltwater",
    "round": "1..N repeat of the whole label list",
    "split": "train or test (test = last round)",
    "window_idx": "index of the ~1 s window inside its run",
    "n_packets": "CSI packets in the window",
    "rssi_mean": "mean RSSI (dBm)",
    "rssi_std": "RSSI standard deviation",
    "level": "mean raw CSI amplitude over the window and all active subcarriers",
    "motion_score": "mean over subcarriers of the std (over the window) of per-packet-normalized amplitude",
    "mean_amp": "per active subcarrier: mean raw amplitude (index order = meta.subcarrier_idx)",
    "var_amp": "per active subcarrier: amplitude variance",
    "shape": "per active subcarrier: mean amplitude after dividing each packet by its own mean",
}


def r(x, n=3):
    return round(float(x), n)


def window_features(A, rssi):
    norm = A / np.maximum(A.mean(axis=1, keepdims=True), 1e-6)
    return {
        "n_packets": int(len(A)),
        "rssi_mean": r(np.mean(rssi), 2),
        "rssi_std": r(np.std(rssi), 2),
        "level": r(A.mean()),
        "motion_score": r(norm.std(axis=0).mean(), 4),
        "mean_amp": np.round(A.mean(axis=0), 3).tolist(),
        "var_amp": np.round(A.var(axis=0), 3).tolist(),
        "shape": np.round(norm.mean(axis=0), 4).tolist(),
    }


def start_reader(args):
    q = queue.Queue()

    def run():
        try:
            for p in packets(args.port, args.baud, args.file):
                q.put(p)
            q.put(None)          # end of a replayed file
        except Exception as e:   # e.g. the port is busy or the cable was pulled
            q.put(e)

    threading.Thread(target=run, daemon=True).start()
    return q


def pull(q, timeout=3.0):
    try:
        p = q.get(timeout=timeout)
    except queue.Empty:
        raise RuntimeError("No CSI packets for 3 seconds. Is the transmitter powered, and the idf.py monitor closed?")
    if isinstance(p, Exception):
        raise p
    return p


def drain(q):
    while not q.empty():
        try:
            q.get_nowait()
        except queue.Empty:
            break


def warmup(q, n=100):
    pk = []
    while len(pk) < n:
        p = pull(q)
        if p is None:
            break
        pk.append(p)
    if len(pk) < 20:
        raise SystemExit("Fewer than 20 packets arrived, so nothing to calibrate on.")
    lens = [len(p["amp"]) for p in pk]
    L = max(set(lens), key=lens.count)   # CSI length can differ by packet type; keep the common one
    pk = [p for p in pk if len(p["amp"]) == L]
    mask = np.stack([p["amp"] for p in pk]).max(axis=0) > 0   # drop always-zero subcarriers
    return L, mask, pk[-1]["channel"]


def record_run(q, L, seconds, trim_s):
    pk, t0, skipped = [], None, 0
    while True:
        p = pull(q)
        if p is None:
            break
        if len(p["amp"]) != L:
            skipped += 1
            continue
        if t0 is None:
            t0 = p["ts_us"]
        el = ((p["ts_us"] - t0) % WRAP) / 1e6
        if el < trim_s:           # settling time, thrown away
            continue
        if el >= trim_s + seconds:
            break
        pk.append(p)
    return pk, skipped


def split_windows(pk, window_s):
    wins, cur, t0 = [], [], None
    for p in pk:
        if t0 is None:
            t0 = p["ts_us"]
        if ((p["ts_us"] - t0) % WRAP) >= window_s * 1e6 and cur:
            wins.append(cur)
            cur, t0 = [], p["ts_us"]
        cur.append(p)
    if cur:
        wins.append(cur)
    if not wins:
        return []
    med = np.median([len(w) for w in wins])
    return [w for w in wins if len(w) >= 0.8 * med]   # drop a short final window


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--port", help="serial port of the XIAO receiver, e.g. COM5")
    ap.add_argument("--file", help="replay a saved CSI log instead of using serial")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--labels", default="baseline,saltwater,saltwater_shake")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seconds", type=float, default=45, help="recorded seconds per run")
    ap.add_argument("--trim", type=float, default=2, help="settling seconds thrown away at the start of each run")
    ap.add_argument("--window", type=float, default=1.0, help="seconds per window")
    ap.add_argument("--out", default="dataset")
    ap.add_argument("--note", default="", help="free text: container, distances, anything that changes between sessions")
    ap.add_argument("--rover-id", default="rover-1")
    ap.add_argument("--checkpoint", default="C0")
    ap.add_argument("--tx", default="devkit-espnow", help="what is transmitting (stored in meta)")
    ap.add_argument("--no-shuffle", action="store_true")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--no-prompt", action="store_true", help="don't wait for Enter before each run")
    args = ap.parse_args()
    if not (args.port or args.file):
        ap.error("give --port COMx (live) or --file log.txt (replay)")

    labels = [x.strip() for x in args.labels.split(",") if x.strip()]
    live = not args.file
    prompt = live and not args.no_prompt
    seed = args.seed if args.seed is not None else random.randrange(10**6)
    rng = random.Random(seed)
    split_of = lambda rnd: "test" if (args.rounds >= 2 and rnd == args.rounds) else "train"
    if args.rounds < 2:
        print("Note: with a single round there is no held-out test split. Use --rounds 2 or more.")

    session = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sdir = os.path.join(args.out, session)
    os.makedirs(sdir)

    q = start_reader(args)
    print("Listening for CSI packets...")
    L, mask, channel = warmup(q)
    idx = np.flatnonzero(mask).tolist()
    print(f"Receiving: channel {channel}, {L // 2} subcarriers, {len(idx)} active.")

    meta = {
        "session": session, "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rover_id": args.rover_id, "checkpoint": args.checkpoint, "tx": args.tx, "note": args.note,
        "channel": channel, "csi_len": L, "subcarrier_idx": idx, "labels": labels,
        "rounds": args.rounds, "seconds_per_run": args.seconds, "trim_s": args.trim,
        "window_s": args.window, "shuffle": not args.no_shuffle, "seed": seed,
        "split_rule": "round == rounds -> test, otherwise train (only when rounds >= 2)",
        "schema": SCHEMA, "runs": [],
    }

    def save_meta():
        with open(os.path.join(sdir, "meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

    plan = []
    for rnd in range(1, args.rounds + 1):
        order = labels[:]
        if not args.no_shuffle:
            rng.shuffle(order)
        plan += [(rnd, lab) for lab in order]

    raw_f = open(os.path.join(sdir, "raw.csv"), "w", newline="")
    rw = csv.writer(raw_f)
    rw.writerow(["run_id", "label", "round", "pkt_id", "ts_us", "rssi"] + [f"amp_{i}" for i in idx])
    win_f = open(os.path.join(sdir, "windows.jsonl"), "w")
    save_meta()

    try:
        for n, (rnd, lab) in enumerate(plan, 1):
            run_id = f"{session}-r{n:02d}"
            print(f"\nRun {n}/{len(plan)}   round {rnd}/{args.rounds}   condition: {lab.upper()}")
            if prompt:
                ans = input("  Set this condition up, keep everything still, then press Enter (q = finish early): ")
                if ans.strip().lower() == "q":
                    break
                drain(q)
                for s in (3, 2, 1):
                    print(f"  starting in {s}...", end="\r", flush=True)
                    time.sleep(1)
            print(f"  recording {args.seconds:g}s (after {args.trim:g}s settling)...")
            pk, skipped = record_run(q, L, args.seconds, args.trim)
            wins = split_windows(pk, args.window)
            if len(wins) < 3:
                print("  too little data in this run; discarded")
                continue
            span = ((pk[-1]["ts_us"] - pk[0]["ts_us"]) % WRAP) / 1e6
            rate = len(pk) / max(span, 1e-6)
            for p in pk:
                rw.writerow([run_id, lab, rnd, p["id"], p["ts_us"], p["rssi"]] + [f"{a:.2f}" for a in p["amp"][mask]])
            motions = []
            for k, w in enumerate(wins):
                A = np.stack([p["amp"] for p in w])[:, mask].astype(np.float64)
                rec = {"session": session, "run_id": run_id, "label": lab, "round": rnd,
                       "split": split_of(rnd), "window_idx": k,
                       "rover_id": args.rover_id, "checkpoint": args.checkpoint}
                rec.update(window_features(A, [p["rssi"] for p in w]))
                win_f.write(json.dumps(rec) + "\n")
                motions.append(rec["motion_score"])
            raw_f.flush()
            win_f.flush()
            meta["runs"].append({"run_id": run_id, "label": lab, "round": rnd, "windows": len(wins),
                                 "pkts_per_s": round(rate, 1), "skipped_packets": skipped})
            save_meta()
            print(f"  saved {len(wins)} windows, {rate:.0f} packets/s, motion {np.mean(motions):.3f}")
            if rate < 60:
                print("  warning: low packet rate; check the transmitter before trusting this run")
            if skipped:
                print(f"  note: {skipped} packets with a different CSI length were skipped")
    except (RuntimeError, KeyboardInterrupt) as e:
        print(f"\nStopped early: {e if str(e) else 'interrupted'}. What was recorded so far is saved.")
    finally:
        raw_f.close()
        win_f.close()
        meta["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        save_meta()

    counts = {}
    for run in meta["runs"]:
        counts[run["label"]] = counts.get(run["label"], 0) + run["windows"]
    print(f"\nDataset saved to {sdir}")
    for lab, c in counts.items():
        print(f"  {lab:<18}{c:>5} windows")
    print(f"\nNext:\n  python analyze.py {os.path.join(sdir, 'windows.jsonl')}\n  python upload.py {sdir} --url <backend>")


if __name__ == "__main__":
    main()
