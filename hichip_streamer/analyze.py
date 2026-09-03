from __future__ import annotations
import argparse, csv, json
from collections import Counter
from pathlib import Path
from .pcapng import iter_pcapng, udp_from_frame
from .protocol import packet_name, parse_f1d0, decode_uid_hello


def main(argv=None):
    ap = argparse.ArgumentParser(description="Analyze a LAN PPPP/HiChip session and generate a reproducible timeline.")
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--camera-ip")
    ap.add_argument("-o", "--out", type=Path, default=Path("hichip-analysis"))
    a = ap.parse_args(argv)
    a.out.mkdir(parents=True, exist_ok=True)
    rows = []
    counts = Counter()
    flows = Counter()
    for no, (iid, link, frame) in enumerate(iter_pcapng(a.pcap), 1):
        u = udp_from_frame(link, frame)
        if not u:
            continue
        src, dst, sp, dp, payload = u
        if a.camera_ip and a.camera_ip not in (src, dst):
            continue
        name = packet_name(payload)
        counts[name] += 1
        flows[(src, sp, dst, dp)] += 1
        d = parse_f1d0(payload)
        uid = decode_uid_hello(payload)
        rows.append({
            "packet": no, "src": src, "src_port": sp, "dst": dst, "dst_port": dp,
            "length": len(payload), "type": name, "prefix": payload[:32].hex(),
            "uid_hint": uid or "", "channel": d["channel"] if d else "",
            "sequence": d["sequence"] if d else "", "session": d["session"] if d else "",
        })
    with (a.out / "timeline.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else ["packet"])
        w.writeheader()
        w.writerows(rows)
    summary = {
        "pcap": str(a.pcap), "camera_ip": a.camera_ip, "packets": len(rows), "types": dict(counts),
        "flows": [{"src": k[0], "src_port": k[1], "dst": k[2], "dst_port": k[3], "packets": v} for k, v in flows.most_common()],
    }
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Related UDP packets: {len(rows)}")
    for k, v in counts.most_common():
        print(f"  {k:16} {v}")
    print(f'Timeline: {a.out / "timeline.csv"}')
    print(f'Summary:  {a.out / "summary.json"}')


if __name__ == "__main__":
    raise SystemExit(main())
