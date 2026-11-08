"""Shared helpers: parse esp-csi CSI_DATA lines and read them from serial or a text file."""
import numpy as np


def parse_line(line):
    """Return a dict for one CSI_DATA line, or None if it isn't one or is damaged."""
    line = line.strip()
    if not line.startswith("CSI_DATA"):
        return None
    i = line.find('"[')
    if i < 0:
        return None
    head = line[:i].rstrip(",").split(",")
    if len(head) < 23:
        return None
    body = line[i + 2:].rstrip().rstrip('"').rstrip("]")
    try:
        raw = np.array([int(x) for x in body.split(",")], dtype=np.int16)
        pkt = {
            "id": int(head[1]),
            "rssi": int(head[3]),
            "channel": int(head[16]),
            "ts_us": int(head[18]),   # board's microsecond clock
            "n_bytes": int(head[22]),
        }
    except ValueError:
        return None
    # Reject lines cut off by a serial glitch
    if raw.size < 2 or raw.size % 2 or raw.size != pkt["n_bytes"]:
        return None
    # Each subcarrier is a pair of int8 values (imaginary, real). Amplitude doesn't
    # depend on which comes first.
    pkt["amp"] = np.hypot(raw[0::2], raw[1::2]).astype(np.float32)
    return pkt


def packets(port=None, baud=115200, file=None):
    """Yield parsed packets from a serial port, or from a saved text file."""
    if file:
        with open(file, "r", errors="ignore") as f:
            for line in f:
                p = parse_line(line)
                if p:
                    yield p
        return
    import serial

    ser = serial.Serial()
    ser.port, ser.baudrate, ser.timeout = port, baud, 1
    ser.dtr = False   # try not to reset the board when the port opens
    ser.rts = False
    ser.open()
    try:
        while True:
            line = ser.readline().decode("utf-8", errors="ignore")
            p = parse_line(line)
            if p:
                yield p
    finally:
        ser.close()
