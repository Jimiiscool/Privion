"""USB keyboard control for an Arduino car."""

import argparse
import time
import tkinter as tk

import serial


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        required=True,
        help="Arduino COM port, for example COM17",
    )
    args = parser.parse_args()

    connection = serial.Serial(
        args.port,
        baudrate=115200,
        timeout=0.1,
        write_timeout=0.2,
    )

    root = None

    try:
        # Allow the board to restart after opening serial.
        time.sleep(2)
        connection.write(b"X")

        root = tk.Tk()
        root.title("Rover keyboard control")
        root.geometry("440x250")

        held = set()
        closing = False

        status = tk.StringVar(value="STOPPED")

        tk.Label(
            root,
            text="Click this window to control the car",
            font=("Arial", 14),
        ).pack(pady=15)

        tk.Label(
            root,
            text=(
                "Hold W: forward    Hold S: reverse\n"
                "Hold A: pivot left    Hold D: pivot right\n\n"
                "Release keys: stop\n"
                "Space: stop    Esc: close"
            ),
            font=("Arial", 12),
        ).pack()

        tk.Label(
            root,
            textvariable=status,
            font=("Arial", 14, "bold"),
        ).pack(pady=15)

        def send(command):
            connection.write(command.encode("ascii"))

        def stop():
            held.clear()
            send("X")
            status.set("STOPPED")

        def close():
            nonlocal closing
            closing = True
            held.clear()

            try:
                send("X")
            except serial.SerialException:
                pass

            root.destroy()

        def key_down(event):
            key = event.keysym.lower()

            if key == "escape":
                close()
            elif key == "space":
                held.clear()
                held.add("space")
            elif key in {"w", "a", "s", "d"}:
                held.add(key)

        def key_up(event):
            held.discard(event.keysym.lower())

        def focus_lost(event):
            try:
                stop()
            except serial.SerialException:
                # The Arduino watchdog handles a lost connection.
                pass

        def tick():
            if closing:
                return

            movement = held & {"w", "a", "s", "d"}

            # Require exactly one movement key.
            # Conflicting keys and Space mean stop.
            command = "X"

            if "space" not in held and len(movement) == 1:
                command = next(iter(movement)).upper()

            names = {
                "W": "FORWARD",
                "S": "REVERSE",
                "A": "LEFT",
                "D": "RIGHT",
                "X": "STOPPED",
            }

            try:
                send(command)
            except serial.SerialException:
                held.clear()
                status.set("DISCONNECTED — close and reconnect")
                return

            status.set(names[command])
            root.after(50, tick)

        root.bind("<KeyPress>", key_down)
        root.bind("<KeyRelease>", key_up)
        root.bind("<FocusOut>", focus_lost)
        root.protocol("WM_DELETE_WINDOW", close)

        root.after(50, tick)
        root.mainloop()

    finally:
        try:
            connection.write(b"X")
        except serial.SerialException:
            pass

        connection.close()


if __name__ == "__main__":
    main()