"""Collect CSI, record labeled datasets, and serve live windows over HTTP."""

import argparse
import csv
import hmac
import json
import os
import queue
import re
import socket
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    RedirectResponse,
    StreamingResponse,
)
from pydantic import BaseModel, Field

from collect import SCHEMA, WRAP, window_features
from csi_common import STATS, packets

try:
    from inference import predict as _predict
except ImportError:
    _predict = None


LIVE_ONLY = {"seq", "recording", "prediction", "feature_schema"}


class Conflict(Exception):
    pass


class Session:
    """One dataset folder containing metadata, windows, and amplitudes."""

    def __init__(self, hub, note, rounds, tx):
        now = datetime.now(timezone.utc)
        base = now.strftime("%Y%m%dT%H%M%SZ")

        self.id, n = base, 1
        while (Path(hub.cfg["dataset_dir"]) / self.id).exists():
            n += 1
            self.id = f"{base}-{n}"

        self.dir = Path(hub.cfg["dataset_dir"]) / self.id
        self.dir.mkdir(parents=True)

        idx = np.flatnonzero(hub.mask).tolist()
        self.key = (hub.L, tuple(idx))
        self.rounds = rounds
        self.n_runs = 0

        self.meta = {
            "session": self.id,
            "started_utc": now.isoformat(timespec="seconds"),
            "rover_id": hub.cfg["rover_id"],
            "tx": tx,
            "note": note,
            "source": hub.source,
            "channel": hub.channel,
            "n_subcarriers": hub.L,
            "subcarrier_idx": idx,
            "rounds": rounds,
            "window_s": hub.cfg["window_s"],
            "split_rule": (
                "round == rounds -> test, otherwise train "
                "(only when rounds >= 2)"
            ),
            "schema": {
                **SCHEMA,
                "timestamp": "UTC time the window closed",
                "checkpoint": "rover position tag at that moment",
            },
            "runs": [],
        }

        self.raw_f = open(self.dir / "raw.csv", "w", newline="")
        self.rw = csv.writer(self.raw_f)
        self.rw.writerow(
            ["run_id", "label", "round", "pkt_id", "ts_us", "rssi"]
            + [f"amp_{i}" for i in idx]
        )

        self.win_f = open(self.dir / "windows.jsonl", "w")
        self.save_meta()

    def split_of(self, rnd):
        if self.rounds >= 2 and rnd == self.rounds:
            return "test"
        return "train"

    def write_window(self, run, rec, pk, mask):
        for p in pk:
            self.rw.writerow(
                [
                    run["run_id"],
                    run["label"],
                    run["round"],
                    p["id"],
                    p["ts_us"],
                    p["rssi"],
                ]
                + [f"{a:.2f}" for a in p["amp"][mask]]
            )

        saved = {
            key: value
            for key, value in rec.items()
            if key not in LIVE_ONLY
        }
        self.win_f.write(json.dumps(saved) + "\n")
        self.raw_f.flush()
        self.win_f.flush()

    def save_meta(self):
        tmp = self.dir / "meta.tmp"
        with open(tmp, "w") as f:
            json.dump(self.meta, f, indent=2)
        tmp.replace(self.dir / "meta.json")

    def close(self):
        self.raw_f.close()
        self.win_f.close()
        self.meta["finished_utc"] = datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds")
        self.save_meta()


class Hub:
    """Shared radio, recording, and live-stream state."""

    def __init__(self):
        self.lock = threading.RLock()
        self.cfg = {
            "rover_id": "rover-1",
            "window_s": 1.0,
            "dataset_dir": "dataset",
            "tx": "devkit-espnow",
        }

        self.source = "none"
        self.error = None
        self.started = time.time()
        self.instance = uuid.uuid4().hex
        self.checkpoint = "C0"

        self.seq = 0
        self.latest = deque(maxlen=600)
        self.subs = set()

        self.session = None
        self.run = None
        self.last_run = None
        self.predict = _predict

        self.packets_total = 0
        self.last_pkt = 0.0
        self.last_window_t = 0.0
        self.rate = 0.0
        self._rate_t = time.time()
        self._rate_n = 0

        self.reset_stream()

    def reset_stream(self):
        with self.lock:
            if self.run:
                self._stop_run()

            self.warm = []
            self.mask = None
            self.L = None
            self.channel = None
            self.skipped = 0
            self.win_pk = []
            self.win_t0 = None
            self.win_run = None

    def set_error(self, msg):
        with self.lock:
            if msg != self.error:
                print(f"[source] {msg}" if msg else "[source] ok")
            self.error = msg

    def _init_mask(self):
        lengths = [len(p["amp"]) for p in self.warm]
        self.L = max(set(lengths), key=lengths.count)

        good = [
            p for p in self.warm
            if len(p["amp"]) == self.L
        ]

        self.mask = (
            np.stack([p["amp"] for p in good]).max(axis=0) > 0
        )
        if not self.mask.any():
            raise ValueError("all CSI subcarriers are zero")

        self.channel = good[-1]["channel"]
        self.warm = []

        print(
            f"[source] receiving CSI: channel {self.channel}, "
            f"{self.L} subcarriers, "
            f"{int(self.mask.sum())} active"
        )

    def on_packet(self, p):
        now = time.time()

        with self.lock:
            self.error = None
            self.last_pkt = now
            self.packets_total += 1
            self._rate_n += 1

            if now - self._rate_t >= 2:
                self.rate = self._rate_n / (now - self._rate_t)
                self._rate_t = now
                self._rate_n = 0

            if self.mask is None:
                self.warm.append(p)
                if len(self.warm) >= 100:
                    self._init_mask()
                return

            if (
                len(p["amp"]) != self.L
                or p["channel"] != self.channel
            ):
                self.skipped += 1
                return

            if (
                self.run
                and self.run["end_at"]
                and time.monotonic() >= self.run["end_at"]
            ):
                self._stop_run()

            if self.win_t0 is None:
                self.win_t0 = p["ts_us"]
                self.win_run = self._recording_run()

            elif (
                (p["ts_us"] - self.win_t0) % WRAP
                >= self.cfg["window_s"] * 1e6
            ):
                self._close_window()
                self.win_t0 = p["ts_us"]
                self.win_run = self._recording_run()

            self.win_pk.append(p)

    def _recording_run(self):
        run = self.run
        if (
            run
            and time.monotonic()
            >= run["start"] + run["trim_s"]
        ):
            return run
        return None

    def _close_window(self):
        pk, self.win_pk = self.win_pk, []

        if len(pk) < 5:
            return

        amplitudes = np.stack(
            [p["amp"] for p in pk]
        )[:, self.mask].astype(np.float64)

        self.seq += 1

        rec = {
            "seq": self.seq,
            "timestamp": datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "rover_id": self.cfg["rover_id"],
            "checkpoint": self.checkpoint,
            "recording": False,
            "run_id": None,
            "label": "unlabeled",
            "session": (
                self.session.id if self.session else None
            ),
            "feature_schema": {
                "channel": self.channel,
                "n_subcarriers": self.L,
                "subcarrier_idx": np.flatnonzero(
                    self.mask
                ).tolist(),
                "window_s": self.cfg["window_s"],
            },
        }

        rec.update(
            window_features(
                amplitudes,
                [p["rssi"] for p in pk],
            )
        )

        run = self.win_run

        # Only save windows entirely belonging to the active run.
        if run is not None and run is self.run:
            rec.update(
                recording=True,
                run_id=run["run_id"],
                label=run["label"],
                round=run["round"],
                split=self.session.split_of(run["round"]),
                window_idx=run["n"],
            )

            run["n"] += 1
            run["motion"].append(rec["motion_score"])

            self.session.write_window(
                run, rec, pk, self.mask
            )

        # Optional server-side inference hook.
        # Remote inference uses teammate.py instead.
        if self.predict:
            try:
                prediction = self.predict(rec)
                if prediction:
                    rec["prediction"] = prediction
            except Exception as exc:
                print(
                    "[inference] predict() failed; "
                    f"turning it off: {exc}"
                )
                self.predict = None

        self.last_window_t = time.time()
        self.latest.append(rec)

        for subscriber in list(self.subs):
            try:
                subscriber.put_nowait(rec)
            except queue.Full:
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(rec)
                except (queue.Empty, queue.Full):
                    pass

    def _csi_flowing(self):
        return (
            bool(self.last_pkt)
            and time.time() - self.last_pkt < 3
        )

    def new_session(self, note, rounds, tx):
        with self.lock:
            if self.run:
                raise Conflict(
                    "stop the current recording first"
                )

            if self.mask is None or not self._csi_flowing():
                raise Conflict("no CSI data is flowing yet")

            if self.session:
                self.session.close()

            self.session = Session(
                self, note, rounds, tx
            )
            return {"session": self.session.id}

    def _ensure_session(self):
        key = (
            self.L,
            tuple(np.flatnonzero(self.mask).tolist()),
        )

        if self.session is None or self.session.key != key:
            if self.session:
                self.session.close()

            self.session = Session(
                self, "", 3, self.cfg["tx"]
            )

        return self.session

    @staticmethod
    def public_run(run):
        if not run:
            return None

        return {
            "run_id": run["run_id"],
            "label": run["label"],
            "round": run["round"],
            "seconds": run["seconds"],
            "trim_s": run["trim_s"],
            "elapsed_s": round(
                time.monotonic() - run["start"], 1
            ),
            "windows": run["n"],
        }

    def start_run(self, label, rnd, seconds, trim_s):
        with self.lock:
            if self.run:
                raise Conflict(
                    "already recording; stop it first"
                )

            if self.mask is None or not self._csi_flowing():
                raise Conflict(
                    "no CSI data is flowing; check the "
                    "receiver, transmitter, and serial port"
                )

            session = self._ensure_session()

            if rnd > session.rounds:
                raise Conflict(
                    "round exceeds session rounds"
                )

            if not label.strip():
                raise Conflict("label cannot be blank")

            session.n_runs += 1
            start = time.monotonic()

            self.run = {
                "run_id": (
                    f"{session.id}-r{session.n_runs:02d}"
                ),
                "label": label,
                "round": rnd,
                "seconds": seconds,
                "trim_s": trim_s,
                "start": start,
                "end_at": (
                    start + trim_s + seconds
                    if seconds else None
                ),
                "raw_offset": session.raw_f.tell(),
                "win_offset": session.win_f.tell(),
                "n": 0,
                "motion": [],
                "started_utc": datetime.now(
                    timezone.utc
                ).isoformat(timespec="seconds"),
            }

            return self.public_run(self.run)

    def _stop_run(self):
        run, self.run = self.run, None

        summary = {
            "run_id": run["run_id"],
            "label": run["label"],
            "round": run["round"],
            "windows": run["n"],
            "mean_motion": (
                round(float(np.mean(run["motion"])), 4)
                if run["motion"] else None
            ),
            "discarded": run["n"] < 3,
        }

        if summary["discarded"]:
            for file, offset in (
                (self.session.raw_f, run["raw_offset"]),
                (self.session.win_f, run["win_offset"]),
            ):
                file.seek(offset)
                file.truncate()
                file.flush()

        else:
            self.session.meta["runs"].append({
                "run_id": run["run_id"],
                "label": run["label"],
                "round": run["round"],
                "windows": run["n"],
                "started_utc": run["started_utc"],
            })
            self.session.save_meta()

        self.last_run = summary

        suffix = (
            " (too few, discarded)"
            if summary["discarded"] else ""
        )
        print(
            f"[record] {run['label']} "
            f"round {run['round']}: "
            f"{run['n']} windows{suffix}"
        )

        return summary

    def stop_run(self):
        with self.lock:
            if not self.run:
                raise Conflict("not recording")
            return self._stop_run()

    def subscribe(self, replay=0):
        subscriber = queue.Queue(maxsize=600)

        with self.lock:
            history = (
                list(self.latest)[-replay:]
                if replay > 0 else []
            )
            for rec in history:
                subscriber.put_nowait(rec)
            self.subs.add(subscriber)

        return subscriber

    def unsubscribe(self, subscriber):
        with self.lock:
            self.subs.discard(subscriber)

    def status(self):
        with self.lock:
            return {
                "server_instance": self.instance,
                "source": self.source,
                "csi_flowing": self._csi_flowing(),
                "error": self.error,
                "packets_total": self.packets_total,
                "packets_per_s": round(self.rate, 1),
                "channel": self.channel,
                "n_subcarriers": self.L,
                "active_subcarriers": (
                    int(self.mask.sum())
                    if self.mask is not None else None
                ),
                "rover_id": self.cfg["rover_id"],
                "checkpoint": self.checkpoint,
                "window_s": self.cfg["window_s"],
                "windows_total": self.seq,
                "last_window_age_s": (
                    round(
                        time.time() - self.last_window_t, 1
                    )
                    if self.last_window_t else None
                ),
                "recording": self.public_run(self.run),
                "last_run": self.last_run,
                "session": (
                    self.session.id
                    if self.session else None
                ),
                "inference_active": bool(
                    self.latest
                    and "prediction" in self.latest[-1]
                ),
                "uptime_s": round(
                    time.time() - self.started
                ),
                "diagnostics": {
                    "serial_lines_seen": STATS["lines"],
                    "csi_lines_rejected": STATS[
                        "csi_rejected"
                    ],
                    "last_rejected_csi_line": STATS[
                        "last_csi_rejected"
                    ],
                    "last_other_line": STATS["last_other"],
                },
            }


hub = Hub()


def auth(request: Request):
    token = os.environ.get("SERVER_TOKEN")

    if (
        not token
        or request.url.path in ("/", "/health")
        or request.method == "OPTIONS"
    ):
        return

    supplied = (
        request.headers.get("authorization", "")
        .removeprefix("Bearer ")
        .strip()
        or request.query_params.get("token", "")
    )

    if not hmac.compare_digest(
        supplied.encode(), token.encode()
    ):
        raise HTTPException(
            status_code=401,
            detail="bad or missing token",
        )


app = FastAPI(
    title="CSI rover data server",
    dependencies=[Depends(auth)],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get(
        "ALLOW_ORIGIN", "*"
    ).split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


class CheckpointBody(BaseModel):
    checkpoint: str = Field(
        min_length=1, max_length=40
    )


class NewSession(BaseModel):
    note: str = Field(default="", max_length=500)
    rounds: int = Field(default=3, ge=1, le=50)
    tx: str = Field(
        default="devkit-espnow", max_length=60
    )


class RecordStart(BaseModel):
    label: str = Field(
        pattern=r"^[A-Za-z0-9_ -]{1,40}$"
    )
    round: int = Field(default=1, ge=1, le=50)
    seconds: float | None = Field(
        default=None, gt=0, le=3600
    )
    trim_s: float = Field(
        default=2.0, ge=0, le=30
    )


def conflict(fn, *args):
    try:
        return fn(*args)
    except Conflict as exc:
        raise HTTPException(
            status_code=409, detail=str(exc)
        ) from exc


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/docs")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/status")
def status():
    return hub.status()


@app.get("/latest")
def latest(n: int = 20, since: int = 0):
    with hub.lock:
        items = [
            rec for rec in hub.latest
            if rec["seq"] > since
        ]

    return items[-max(1, min(n, 600)):]


@app.get("/stream")
def stream(replay: int = 0):
    subscriber = hub.subscribe(min(replay, 600))

    def generate():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    rec = subscriber.get(timeout=15)
                    yield f"data: {json.dumps(rec)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            hub.unsubscribe(subscriber)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/checkpoint")
def set_checkpoint(body: CheckpointBody):
    with hub.lock:
        hub.checkpoint = body.checkpoint
    return {"checkpoint": body.checkpoint}


@app.post("/session/new")
def session_new(body: NewSession):
    return conflict(
        hub.new_session,
        body.note,
        body.rounds,
        body.tx,
    )


@app.post("/record/start")
def record_start(body: RecordStart):
    return conflict(
        hub.start_run,
        body.label.strip(),
        body.round,
        body.seconds,
        body.trim_s,
    )


@app.post("/record/stop")
def record_stop():
    return conflict(hub.stop_run)


def dataset_dir(sid):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", sid):
        raise HTTPException(
            status_code=404,
            detail="invalid session ID",
        )

    directory = Path(hub.cfg["dataset_dir"]) / sid
    if not (directory / "meta.json").exists():
        raise HTTPException(
            status_code=404,
            detail="no such session",
        )

    return directory


@app.get("/datasets")
def datasets():
    root = Path(hub.cfg["dataset_dir"])
    result = []

    if root.exists():
        for directory in sorted(
            root.iterdir(), reverse=True
        ):
            if (
                directory.is_dir()
                and (directory / "meta.json").exists()
            ):
                with open(
                    directory / "meta.json"
                ) as file:
                    meta = json.load(file)

                counts = {}
                for run in meta.get("runs", []):
                    label = run["label"]
                    counts[label] = (
                        counts.get(label, 0)
                        + run["windows"]
                    )

                result.append({
                    "session": directory.name,
                    "started_utc": meta.get(
                        "started_utc"
                    ),
                    "note": meta.get("note"),
                    "runs": len(meta.get("runs", [])),
                    "windows_by_label": counts,
                })

    return result


@app.get("/datasets/{sid}/meta")
def dataset_meta(sid: str):
    with open(dataset_dir(sid) / "meta.json") as file:
        return json.load(file)


@app.get("/datasets/{sid}/windows")
def dataset_windows(sid: str):
    return FileResponse(
        dataset_dir(sid) / "windows.jsonl",
        media_type="application/x-ndjson",
        filename=f"{sid}-windows.jsonl",
    )


@app.get("/datasets/{sid}/raw")
def dataset_raw(sid: str):
    return FileResponse(
        dataset_dir(sid) / "raw.csv",
        media_type="text/csv",
        filename=f"{sid}-raw.csv",
    )


def paced(file, loop):
    """Replay a log at approximately its original packet rate."""
    virtual_time, previous = 0, None

    while True:
        for packet in packets(file=file):
            if previous is not None:
                delay = (
                    (packet["ts_us"] - previous) % WRAP
                ) / 1e6

                if delay > 0.5:
                    delay = 0.01

                time.sleep(delay)
                virtual_time += int(delay * 1e6)

            previous = packet["ts_us"]
            packet["ts_us"] = virtual_time % WRAP
            yield packet

        if not loop:
            return

        previous = None


def reader(args):
    while True:
        try:
            hub.reset_stream()

            source = (
                paced(args.file, args.loop)
                if args.file
                else packets(args.serial, args.baud)
            )

            for packet in source:
                hub.on_packet(packet)

            if args.file and not args.loop:
                hub.set_error("replay finished")
                return

        except Exception as exc:
            hub.set_error(
                f"{type(exc).__name__}: {exc}"
            )

        time.sleep(3)


def recording_timer():
    """Stop timed runs even if the receiver goes silent."""
    while True:
        with hub.lock:
            if (
                hub.run
                and hub.run["end_at"]
                and time.monotonic()
                >= hub.run["end_at"]
            ):
                hub._stop_run()

        time.sleep(0.1)


def lan_addresses():
    try:
        return sorted({
            ip
            for ip in socket.gethostbyname_ex(
                socket.gethostname()
            )[2]
            if not ip.startswith("127.")
        })
    except OSError:
        return []


def main():
    parser = argparse.ArgumentParser(
        description=__doc__
    )
    parser.add_argument("--serial")
    parser.add_argument("--file")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument(
        "--baud", type=int, default=115200
    )
    parser.add_argument(
        "--http-port", type=int, default=8000
    )
    parser.add_argument(
        "--host", default="0.0.0.0"
    )
    parser.add_argument(
        "--dataset-dir", default="dataset"
    )
    parser.add_argument(
        "--rover-id", default="rover-1"
    )
    parser.add_argument(
        "--window", type=float, default=1.0
    )
    args = parser.parse_args()

    if bool(args.serial) == bool(args.file):
        parser.error(
            "give exactly one of --serial COMx "
            "or --file log.txt"
        )

    if args.window <= 0:
        parser.error("--window must be positive")

    hub.cfg.update(
        rover_id=args.rover_id,
        window_s=args.window,
        dataset_dir=args.dataset_dir,
    )
    hub.source = (
        f"replay {args.file}"
        if args.file else f"serial {args.serial}"
    )

    threading.Thread(
        target=reader,
        args=(args,),
        daemon=True,
    ).start()

    threading.Thread(
        target=recording_timer,
        daemon=True,
    ).start()

    print(f"CSI server, source: {hub.source}")

    if args.host != "127.0.0.1":
        for ip in lan_addresses():
            print(
                f"  Network URL: "
                f"http://{ip}:{args.http_port}"
            )

    print(
        f"  Local URL: "
        f"http://localhost:{args.http_port}"
    )

    if not os.environ.get("SERVER_TOKEN"):
        print(
            "WARNING: SERVER_TOKEN is unset. "
            "API authentication is disabled."
        )

    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.http_port,
            log_level="warning",
        )
    finally:
        with hub.lock:
            if hub.run:
                hub._stop_run()
            if hub.session:
                hub.session.close()


if __name__ == "__main__":
    main()