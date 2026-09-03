from __future__ import annotations
import argparse, select, socket, sys, time
from .protocol import packet_name, decode_uid_hello


def bind_udp(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.setblocking(False)
    return s


def main(argv=None):
    ap = argparse.ArgumentParser(description="Experimental LAN probe for validating the PPPP handshake without the vendor app.")
    ap.add_argument("--camera-ip", required=True)
    ap.add_argument("--ports", default="52314,52315")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--respond-hello", action="store_true", help="Reply with F142 to F141 announcements (experimental).")
    a = ap.parse_args(argv)
    ports = [int(x) for x in a.ports.split(",")]
    socks = []
    try:
        for p in ports:
            socks.append(bind_udp(p))
            print(f"Listening on UDP 0.0.0.0:{p}", file=sys.stderr)
    except OSError as exc:
        print(f"Unable to bind UDP port: {exc}", file=sys.stderr)
        return 2
    end = time.monotonic() + a.seconds
    seen = 0
    while time.monotonic() < end:
        ready, _, _ = select.select(socks, [], [], 1.0)
        for s in ready:
            data, (ip, port) = s.recvfrom(65535)
            if ip != a.camera_ip:
                continue
            seen += 1
            typ = packet_name(data)
            uid = decode_uid_hello(data)
            print(f'{time.strftime("%H:%M:%S")} {ip}:{port} -> local:{s.getsockname()[1]} {typ} len={len(data)} {data[:32].hex()}', file=sys.stderr)
            if uid:
                print(f"  Approximate UID: {uid}", file=sys.stderr)
            if a.respond_hello and data[:2] == b"\xf1A" and len(data) == 24:
                reply = b"\xf1B" + data[2:]
                s.sendto(reply, (ip, port))
                print("  -> F142 sent", file=sys.stderr)
    print(f"Done. Camera packets observed: {seen}", file=sys.stderr)
    return 0 if seen else 3


if __name__ == "__main__":
    raise SystemExit(main())
