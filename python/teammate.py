"""Record, download, train a baseline, and classify live CSI."""

import argparse
import json
import os
import random
import re
import time
from pathlib import Path

import httpx


class API:
    def __init__(self, url, token):
        headers = (
            {"Authorization": f"Bearer {token}"}
            if token else {}
        )
        self.client = httpx.Client(
            base_url=url.rstrip("/") + "/",
            timeout=30,
            headers=headers,
        )

    def get(self, path, **params):
        response = self.client.get(
            path.lstrip("/"), params=params
        )
        response.raise_for_status()
        return response.json()

    def post(self, path, body):
        response = self.client.post(
            path.lstrip("/"), json=body
        )
        response.raise_for_status()
        return response.json()


def schema(meta):
    return {
        "channel": meta["channel"],
        "n_subcarriers": meta.get(
            "n_subcarriers", meta.get("csi_len")
        ),
        "subcarrier_idx": meta["subcarrier_idx"],
        "window_s": meta["window_s"],
    }


def vector(rec):
    """Identical feature ordering for training and inference."""
    return (
        rec["shape"]
        + rec["mean_amp"]
        + rec["var_amp"]
        + [
            rec[key]
            for key in (
                "rssi_mean",
                "rssi_std",
                "level",
                "motion_score",
                "n_packets",
            )
        ]
    )


def record(api, args):
    labels = [
        value.strip()
        for value in args.labels.split(",")
        if value.strip()
    ]

    if (
        len(set(labels)) < 2
        or any(
            not re.fullmatch(
                r"[A-Za-z0-9_ -]{1,40}", label
            )
            for label in labels
        )
    ):
        raise ValueError(
            "Provide at least two distinct labels using "
            "letters, numbers, spaces, _ or -."
        )

    if not api.get("status")["csi_flowing"]:
        raise ValueError(
            "No CSI flowing. Check status and "
            "wait for receiver warmup."
        )

    session = api.post(
        "session/new",
        {
            "note": args.note,
            "rounds": args.rounds,
        },
    )["session"]

    print("Session:", session, flush=True)

    try:
        for rnd in range(1, args.rounds + 1):
            order = labels[:]
            random.shuffle(order)

            for label in order:
                input(
                    f"Round {rnd}/{args.rounds}: "
                    f"set up {label!r}, then press Enter: "
                )

                run = api.post(
                    "record/start",
                    {
                        "label": label,
                        "round": rnd,
                        "seconds": args.seconds,
                        "trim_s": 2,
                    },
                )

                deadline = (
                    time.monotonic() + args.seconds + 32
                )

                while True:
                    state = api.get("status")

                    if not state["recording"]:
                        result = state["last_run"]

                        if (
                            not result
                            or result["run_id"]
                            != run["run_id"]
                        ):
                            raise RuntimeError(
                                "Recording state changed "
                                "unexpectedly."
                            )

                        print(
                            json.dumps(result), flush=True
                        )

                        if (
                            result["discarded"]
                            or not state["csi_flowing"]
                        ):
                            raise RuntimeError(
                                "Run failed or CSI stopped; "
                                "check the source."
                            )

                        break

                    if time.monotonic() > deadline:
                        raise RuntimeError(
                            "Recording did not auto-stop; "
                            "check the server."
                        )

                    time.sleep(0.5)

    except (KeyboardInterrupt, Exception):
        try:
            if api.get("status")["recording"]:
                print(
                    "Stopping:",
                    api.post("record/stop", {}),
                )
        except Exception:
            print(
                "Could not stop remotely; "
                "check server status."
            )
        raise

    print(
        "Finished. Download with:\n"
        f"python teammate.py --url {args.url} "
        f"fetch {session}"
    )


def fetch(api, args):
    sid = args.session

    if not re.fullmatch(r"[A-Za-z0-9_-]+", sid):
        raise ValueError("Invalid session ID")

    state = api.get("status")

    if (
        state["session"] == sid
        and state["recording"]
    ):
        raise ValueError(
            "Stop recording before downloading "
            "a training snapshot."
        )

    destination = Path(args.out) / sid
    destination.mkdir(parents=True, exist_ok=True)

    files = [
        ("meta", "meta.json"),
        ("windows", "windows.jsonl"),
    ]
    if args.raw:
        files.append(("raw", "raw.csv"))

    # Do not start another recording during this download.
    for endpoint, name in files:
        temporary = destination / (name + ".part")

        with api.client.stream(
            "GET", f"datasets/{sid}/{endpoint}"
        ) as response:
            response.raise_for_status()

            with temporary.open("wb") as file:
                for chunk in response.iter_bytes():
                    file.write(chunk)

        temporary.replace(destination / name)

    print("Saved:", destination)


def train(args):
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
    )

    folder = Path(args.folder)
    meta = json.loads(
        (folder / "meta.json").read_text()
    )
    valid_runs = {
        run["run_id"] for run in meta["runs"]
    }

    rows = [
        json.loads(line)
        for line in (
            folder / "windows.jsonl"
        ).read_text().splitlines()
        if line.strip()
    ]
    rows = [
        row for row in rows
        if row.get("run_id") in valid_runs
    ]

    training = [
        row for row in rows
        if row["split"] == "train"
    ]
    testing = [
        row for row in rows
        if row["split"] == "test"
    ]

    training_labels = {
        row["label"] for row in training
    }
    testing_labels = {
        row["label"] for row in testing
    }

    if len(training_labels) < 2 or not testing:
        raise ValueError(
            "Need at least two training classes and "
            "a held-out test round. Record every "
            "class in at least two rounds."
        )

    if testing_labels != training_labels:
        raise ValueError(
            "Train/test label sets differ. Record "
            "all labels in the final round too."
        )

    training_runs = {
        row["run_id"] for row in training
    }
    testing_runs = {
        row["run_id"] for row in testing
    }

    if training_runs & testing_runs:
        raise ValueError(
            "A run occurs in both splits."
        )

    expected_width = (
        3 * len(meta["subcarrier_idx"]) + 5
    )

    X = np.array(
        [vector(row) for row in training],
        dtype=float,
    )
    X_test = np.array(
        [vector(row) for row in testing],
        dtype=float,
    )

    if (
        X.shape[1] != expected_width
        or X_test.shape[1] != expected_width
        or not np.isfinite(X).all()
        or not np.isfinite(X_test).all()
    ):
        raise ValueError(
            "Invalid feature width or non-finite data"
        )

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X,
        [row["label"] for row in training],
    )

    truth = [row["label"] for row in testing]
    predictions = model.predict(X_test)

    print(
        classification_report(
            truth,
            predictions,
            zero_division=0,
        )
    )
    print(
        "Confusion matrix, labels:",
        model.classes_.tolist(),
    )
    print(
        confusion_matrix(
            truth,
            predictions,
            labels=model.classes_,
        )
    )

    joblib.dump(
        {
            "format": 1,
            "schema": schema(meta),
            "model": model,
            "session": meta["session"],
        },
        args.model,
    )

    print("Saved:", args.model)


def live(api, args):
    import joblib

    # Load only trusted models: joblib files can execute code.
    artifact = joblib.load(args.model)

    if artifact["format"] != 1:
        raise ValueError(
            "Unsupported model format"
        )

    cursor = 0
    instance = None

    while True:
        state = api.get("status")

        if instance != state["server_instance"]:
            instance = state["server_instance"]
            cursor = 0

        windows = api.get(
            "latest", since=cursor, n=600
        )

        for rec in windows:
            if cursor and rec["seq"] > cursor + 1:
                print(json.dumps({
                    "warning": (
                        "Live history gap; missed windows "
                        "are not recoverable from /latest."
                    )
                }))

            cursor = rec["seq"]

            if rec["feature_schema"] != artifact["schema"]:
                raise ValueError(
                    "Live channel/subcarrier mask/window "
                    "differs from training. Recollect or "
                    "retrain with this setup."
                )

            probabilities = artifact[
                "model"
            ].predict_proba([vector(rec)])[0]

            classes = artifact["model"].classes_
            best = int(probabilities.argmax())

            result = {
                "server_instance": instance,
                "seq": cursor,
                "timestamp": rec["timestamp"],
                "checkpoint": rec["checkpoint"],
                "label": str(classes[best]),
                "class_probability": float(
                    probabilities[best]
                ),
                "probabilities": dict(
                    zip(
                        classes.tolist(),
                        probabilities.tolist(),
                    )
                ),
            }

            print(json.dumps(result), flush=True)

        if not state["csi_flowing"]:
            print(
                json.dumps({
                    "warning": (
                        "CSI source is stale; no fresh "
                        "classification available."
                    )
                }),
                flush=True,
            )

        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--url",
        default=os.getenv(
            "CSI_SERVER_URL",
            "http://127.0.0.1:8000",
        ),
    )
    parser.add_argument(
        "--token",
        default=os.getenv("SERVER_TOKEN", ""),
        help="Prefer SERVER_TOKEN environment variable",
    )

    commands = parser.add_subparsers(
        dest="command", required=True
    )

    commands.add_parser("status")
    commands.add_parser("datasets")

    recording = commands.add_parser("record")
    recording.add_argument(
        "--labels", default="baseline,disturbance"
    )
    recording.add_argument(
        "--rounds", type=int, default=3
    )
    recording.add_argument(
        "--seconds", type=float, default=45
    )
    recording.add_argument("--note", default="")

    download = commands.add_parser("fetch")
    download.add_argument("session")
    download.add_argument(
        "--out", default="downloaded"
    )
    download.add_argument(
        "--raw", action="store_true"
    )

    training = commands.add_parser("train")
    training.add_argument("folder")
    training.add_argument(
        "--model", default="model.joblib"
    )

    inference = commands.add_parser("live")
    inference.add_argument(
        "--model", default="model.joblib"
    )

    args = parser.parse_args()

    if args.command == "train":
        train(args)
        return

    api = API(args.url, args.token)

    try:
        if args.command in ("status", "datasets"):
            print(
                json.dumps(
                    api.get(args.command),
                    indent=2,
                )
            )

        elif args.command == "record":
            if (
                not 2 <= args.rounds <= 50
                or not 0 < args.seconds <= 3600
            ):
                parser.error(
                    "Use 2..50 rounds and "
                    "0 < seconds <= 3600"
                )

            record(api, args)

        elif args.command == "fetch":
            fetch(api, args)

        else:
            live(api, args)

    finally:
        api.client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (
        ValueError,
        RuntimeError,
        OSError,
        httpx.HTTPError,
    ) as exc:
        raise SystemExit(str(exc))