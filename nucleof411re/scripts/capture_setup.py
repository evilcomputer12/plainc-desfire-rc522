#!/usr/bin/env python3
"""Capture Nucleo serial log for df setup. Close screen/other clients on the port first."""
import argparse
import sys
import time

try:
    import serial
except ImportError:
    print("Install pyserial: python3 -m venv .venv-serial && .venv-serial/bin/pip install pyserial", file=sys.stderr)
    sys.exit(1)


def wait_for(port: str, needle: bytes, timeout: float) -> bytes:
    buf = b""
    deadline = time.time() + timeout
    with serial.Serial(port, 115200, timeout=0.2) as ser:
        while time.time() < deadline:
            chunk = ser.read(4096)
            if chunk:
                buf += chunk
                if needle in buf:
                    return buf
            time.sleep(0.05)
    return buf


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", default="/dev/cu.usbmodem1443203")
    ap.add_argument("-o", "--out", help="Save full log to file")
    args = ap.parse_args()

    try:
        ser = serial.Serial(args.port, 115200, timeout=0.25)
    except serial.SerialException as e:
        print(f"Cannot open {args.port}: {e}", file=sys.stderr)
        print("Close screen/minicom on this port and retry.", file=sys.stderr)
        return 1

    log = b""
    try:
        time.sleep(2.0)
        log += ser.read(16384)

        print("Waiting for shell banner / nfc> prompt...")
        deadline = time.time() + 20.0
        while time.time() < deadline:
            chunk = ser.read(4096)
            if chunk:
                log += chunk
            if b"Interactive NFC shell ready" in log or b"nfc>" in log:
                break
            time.sleep(0.05)
        else:
            print("WARNING: shell prompt not seen — is firmware running?", file=sys.stderr)

        ser.write(b"df setup -y\r\n")
        print("Sent: df setup -y (auto, no Enter prompt)")

        sent_ready_enter = False
        idle_since = time.time()
        deadline = time.time() + 180.0
        while time.time() < deadline:
            chunk = ser.read(4096)
            if chunk:
                log += chunk
                idle_since = time.time()
                if any(
                    m in log
                    for m in (
                        b"SETUP FAILED",
                        b"DF setup complete",
                        b"df setup failed",
                        b"ChangeKey (0xC4)",
                    )
                ):
                    time.sleep(1.5)
                    log += ser.read(8192)
                    break
            elif sent_ready_enter and time.time() - idle_since > 90.0:
                print("Timeout waiting for setup result (card on reader?)", file=sys.stderr)
                break
            elif log and not sent_ready_enter and time.time() - idle_since > 8.0:
                break
            if (
                not sent_ready_enter
                and b"Place the card" in log
                and b"Ready?" in log
            ):
                ser.write(b"\r\n")
                sent_ready_enter = True
                print("Sent: Enter (card on reader now)")
                idle_since = time.time()
            if b"Auto: place card" in log:
                sent_ready_enter = True
            time.sleep(0.05)
    finally:
        ser.close()

    text = log.decode("utf-8", errors="replace")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)

    print("\n=== FULL LOG ===\n")
    print(text)
    print("\n=== KEY LINES ===\n")
    for line in text.splitlines():
        if any(k in line for k in ("[P4]", "[NFC]", "RATS", "ChangeKey", "SETUP FAILED", "setup complete", "activate:")):
            print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
