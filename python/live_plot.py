"""Live view of CSI from the XIAO: a heatmap of amplitude per subcarrier over the last
few seconds, plus a motion trace underneath. Wave a hand between the XIAO and the
hotspot and watch the trace.

  python live_plot.py --port COM5

Close the idf.py monitor first: only one program can use the COM port.
"""
import argparse
import collections
import threading
import time

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.animation import FuncAnimation

from csi_common import packets

ap = argparse.ArgumentParser()
ap.add_argument("--port", required=True, help="e.g. COM5")
ap.add_argument("--baud", type=int, default=115200)
ap.add_argument("--history", type=int, default=600, help="packets shown (~100 per second)")
ap.add_argument("--ymax", type=float, default=0.6, help="top of the motion trace axis")
args = ap.parse_args()

hist = collections.deque(maxlen=args.history)
lock = threading.Lock()
st = {"mask": None, "count": 0, "t0": time.time()}


def add(amp):
    a = amp[st["mask"]]                       # drop always-zero (guard) subcarriers
    hist.append(a / max(float(a.mean()), 1e-6))  # remove packet-to-packet gain changes


def reader():
    warm = []
    for p in packets(args.port, args.baud):
        with lock:
            st["count"] += 1
            if st["mask"] is None:
                warm.append(p["amp"])
                if len(warm) >= 50:
                    st["mask"] = np.stack(warm).max(axis=0) > 0
                    for a in warm:
                        add(a)
                continue
            add(p["amp"])


threading.Thread(target=reader, daemon=True).start()

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7))
img = ax1.imshow(np.zeros((10, 10)), aspect="auto", vmin=0, vmax=2.5, cmap="viridis")
ax1.set_title("Normalized CSI amplitude (subcarriers vs. recent packets)")
ax1.set_ylabel("subcarrier")
(line,) = ax2.plot([], [])
ax2.set_title("Motion trace: packet-to-packet change (higher = more disturbance)")
ax2.set_xlabel("recent packets (oldest to newest)")
ax2.set_xlim(0, args.history)
ax2.set_ylim(0, args.ymax)
rate_txt = ax2.text(0.01, 0.88, "", transform=ax2.transAxes)


def update(_):
    with lock:
        if len(hist) < 30:
            return
        M = np.stack(hist)
        n = st["count"]
    diff = np.abs(np.diff(M, axis=0)).mean(axis=1)
    motion = np.convolve(diff, np.ones(10) / 10, mode="same")
    img.set_data(M.T)
    img.set_extent((0, M.shape[0], M.shape[1], 0))
    line.set_data(np.arange(len(motion)), motion)
    rate_txt.set_text(f"{n / (time.time() - st['t0']):.0f} packets/s   now: {motion[-15:].mean():.3f}")


ani = FuncAnimation(fig, update, interval=100, cache_frame_data=False)
plt.tight_layout()
plt.show()
