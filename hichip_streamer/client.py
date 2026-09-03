from __future__ import annotations

import argparse
import select
import socket
import sys
import time
import struct
import subprocess
import shutil
import queue
import threading
import mimetypes
import os
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from dataclasses import dataclass

from .protocol import packet_name

DISCOVER = b"\xf1\x30\x00\x00"


def load_aes_decryptor():
    """Load AES-ECB support only when video decryption is required.

    cryptography is preferred; PyCryptodome is supported as a fallback.
    Returns a decrypt(key, data) -> bytes function.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def decrypt(key: bytes, data: bytes) -> bytes:
            ctx = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            return ctx.update(data) + ctx.finalize()

        return decrypt
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES

        def decrypt(key: bytes, data: bytes) -> bytes:
            return AES.new(key, AES.MODE_ECB).decrypt(data)

        return decrypt
    except ImportError:
        return None


def decrypt_video_prefix_96(payload: bytes, key: bytes, aes_decrypt) -> bytes:
    """Offline-validated decryption: AES-128 ECB + XOR 0x3F on the first 96 bytes."""
    n = min(96, (len(payload) // 16) * 16)
    if n == 0:
        return payload
    plain = aes_decrypt(key, payload[:n])
    return bytes(b ^ 0x3F for b in plain) + payload[n:]


def annexb_nal_types(payload: bytes) -> list[int]:
    """Return the HEVC NAL unit types found in an Annex-B payload."""
    starts: list[tuple[int, int]] = []
    i = 0
    n = len(payload)
    while i + 4 <= n:
        if payload[i:i+4] == b"\x00\x00\x00\x01":
            starts.append((i, 4))
            i += 4
            continue
        if payload[i:i+3] == b"\x00\x00\x01":
            starts.append((i, 3))
            i += 3
            continue
        i += 1
    out: list[int] = []
    for pos, sc_len in starts:
        hdr = pos + sc_len
        if hdr < n:
            out.append((payload[hdr] >> 1) & 0x3F)
    return out


def is_clean_irap_start(nal_types: list[int]) -> bool:
    """Require VPS/SPS/PPS parameters and at least one IRAP picture (16..23)."""
    nts = set(nal_types)
    return 32 in nts and 33 in nts and 34 in nts and any(16 <= t <= 23 for t in nts)





class RotatingLogWriter:
    """File-like stderr sink with simple size-based rotation.

    Keeps the existing print(..., file=sys.stderr) calls usable while making
    long-running/service deployments safe. Rotation is intentionally simple
    and dependency-free so it works inside the PyInstaller executable.
    """
    def __init__(self, path: str | None, max_bytes: int, backups: int, console=None):
        self.path = Path(path).resolve() if path else None
        self.max_bytes = max(64 * 1024, int(max_bytes))
        self.backups = max(1, int(backups))
        self.console = console
        self.lock = threading.Lock()
        self.file = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.file = open(self.path, "a", encoding="utf-8", buffering=1)

    def _rotate_if_needed(self) -> None:
        if not self.path or not self.file:
            return
        try:
            self.file.flush()
            if self.path.stat().st_size < self.max_bytes:
                return
        except OSError:
            return
        try:
            self.file.close()
        except Exception:
            pass
        for i in range(self.backups - 1, 0, -1):
            src = Path(f"{self.path}.{i}")
            dst = Path(f"{self.path}.{i+1}")
            if src.exists():
                try:
                    if dst.exists():
                        dst.unlink()
                    src.replace(dst)
                except OSError:
                    pass
        first = Path(f"{self.path}.1")
        try:
            if first.exists():
                first.unlink()
            if self.path.exists():
                self.path.replace(first)
        except OSError:
            pass
        self.file = open(self.path, "a", encoding="utf-8", buffering=1)

    def write(self, text: str) -> int:
        if not text:
            return 0
        with self.lock:
            if self.console is not None:
                try:
                    self.console.write(text)
                    self.console.flush()
                except Exception:
                    pass
            if self.file is not None:
                try:
                    self.file.write(text)
                    self.file.flush()
                    self._rotate_if_needed()
                except Exception:
                    pass
        return len(text)

    def flush(self) -> None:
        with self.lock:
            if self.console is not None:
                try: self.console.flush()
                except Exception: pass
            if self.file is not None:
                try: self.file.flush()
                except Exception: pass

    def close(self) -> None:
        with self.lock:
            if self.file is not None:
                try: self.file.close()
                except Exception: pass
                self.file = None

class HlsHttpHandler(SimpleHTTPRequestHandler):
    """Minimal static server for HLS testing without locking the playlist on NTFS."""
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".m3u8": "application/vnd.apple.mpegurl",
        ".ts": "video/mp2t",
    }

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        # Avoid one console line per segment/playlist refresh.
        return


class HlsHttpServer:
    def __init__(self, directory: str | None, bind: str, port: int):
        self.directory = Path(directory).resolve() if directory else None
        self.bind = bind
        self.port = port
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> bool:
        if self.directory is None or self.port <= 0:
            return False
        self.directory.mkdir(parents=True, exist_ok=True)
        handler = partial(HlsHttpHandler, directory=str(self.directory))
        try:
            self.httpd = ThreadingHTTPServer((self.bind, self.port), handler)
            self.httpd.daemon_threads = True
        except OSError as exc:
            print(f"HLS HTTP WARNING: unable to listen on {self.bind}:{self.port}: {exc}", file=sys.stderr, flush=True)
            return False
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="hls-http", daemon=True)
        self.thread.start()
        shown_host = "127.0.0.1" if self.bind in ("0.0.0.0", "") else self.bind
        print(f"HLS HTTP: http://{shown_host}:{self.port}/index.m3u8", file=sys.stderr, flush=True)
        return True

    def close(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        self.thread = None


class FfmpegHlsSink:
    """Feed Annex-B HEVC to FFmpeg without blocking the PPPP/D102 loop.

    Since v0.21.3 FFmpeg is fed by a writer thread through a bounded queue.
    Earlier builds called stdin.write() in the receive/ACK loop, so encoder
    back-pressure could block UDP processing and stop video delivery. The
    network path is now fully decoupled from the HLS encoder.
    """

    def __init__(self, ffmpeg: str, out_dir: str | None, fps: float, hls_time: float, list_size: int):
        self.ffmpeg = ffmpeg
        self.out_dir = Path(out_dir).resolve() if out_dir else None
        self.fps = fps
        self.hls_time = hls_time
        self.list_size = list_size
        self.proc: subprocess.Popen | None = None
        self.failed = False
        self.bytes_written = 0
        self.bytes_queued = 0
        self.queue_highwater = 0
        self.q: queue.Queue[bytes | None] = queue.Queue(maxsize=256)
        self.writer: threading.Thread | None = None
        self._failure_reported = False

    @property
    def enabled(self) -> bool:
        return self.out_dir is not None

    def _writer_loop(self) -> None:
        assert self.proc is not None
        try:
            assert self.proc.stdin is not None
            while True:
                payload = self.q.get()
                if payload is None:
                    break
                self.proc.stdin.write(payload)
                self.bytes_written += len(payload)
        except (BrokenPipeError, OSError) as exc:
            self.failed = True
            print(f"HLS WARNING: FFmpeg pipe closed: {exc}", file=sys.stderr, flush=True)
        finally:
            try:
                if self.proc and self.proc.stdin:
                    self.proc.stdin.close()
            except OSError:
                pass

    def start(self) -> bool:
        if not self.enabled or self.proc is not None or self.failed:
            return self.proc is not None
        ffmpeg_cmd = self.ffmpeg
        if ffmpeg_cmd == "ffmpeg":
            executable_dir = (
                Path(sys.executable).resolve().parent
                if getattr(sys, "frozen", False)
                else Path(__file__).resolve().parent.parent
            )
            local_ffmpeg = executable_dir / ("ffmpeg.exe" if os.name == "nt" else "ffmpeg")
            if local_ffmpeg.is_file():
                ffmpeg_cmd = str(local_ffmpeg)
        exe = ffmpeg_cmd if Path(ffmpeg_cmd).is_file() else shutil.which(ffmpeg_cmd)
        if not exe:
            print(
                f"HLS WARNING: FFmpeg was not found ({ffmpeg_cmd!r}); continuing without HLS.",
                file=sys.stderr, flush=True,
            )
            self.failed = True
            return False
        self.ffmpeg = str(exe)

        self.out_dir.mkdir(parents=True, exist_ok=True)
        for old in self.out_dir.glob("seg_*.ts"):
            try: old.unlink()
            except OSError: pass
        for old_name in ("index.m3u8", "index.m3u8.tmp"):
            try: (self.out_dir / old_name).unlink()
            except OSError: pass

        playlist = self.out_dir / "index.m3u8"
        segment_pattern = self.out_dir / "seg_%06d.ts"
        gop = max(1, round(self.fps * self.hls_time))
        cmd = [
            str(exe),
            "-hide_banner",
            "-loglevel", "warning",
            "-framerate", str(self.fps),
            "-f", "hevc",
            "-i", "pipe:0",
            "-map", "0:v:0",
            "-an",
            "-vf", "scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2",
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-pix_fmt", "yuv420p",
            "-b:v", "2500k",
            "-maxrate", "3000k",
            "-bufsize", "5000k",
            "-g", str(gop),
            "-keyint_min", str(gop),
            "-sc_threshold", "0",
            "-force_key_frames", f"expr:gte(t,n_forced*{self.hls_time})",
            "-f", "hls",
            "-hls_time", str(self.hls_time),
            "-hls_list_size", str(self.list_size),
            "-hls_flags", "delete_segments+omit_endlist+program_date_time+independent_segments",
            "-hls_segment_filename", str(segment_pattern),
            str(playlist),
        ]
        print(
            f"HLS: asynchronous FFmpeg HEVC->H.264 1280x720, {self.fps:g} fps, IDR every {self.hls_time:g}s.",
            file=sys.stderr, flush=True,
        )
        print("HLS: D102 receive/ACK no longer waits for FFmpeg.", file=sys.stderr, flush=True)
        print(f"HLS PLAYLIST: {playlist}", file=sys.stderr, flush=True)
        try:
            self.proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=None, bufsize=0
            )
        except OSError as exc:
            print(f"HLS WARNING: unable to start FFmpeg: {exc}", file=sys.stderr, flush=True)
            self.proc = None
            self.failed = True
            return False
        self.writer = threading.Thread(target=self._writer_loop, name="hls-ffmpeg-writer", daemon=True)
        self.writer.start()
        return True

    def write(self, payload: bytes) -> None:
        if not self.enabled or self.failed:
            return
        if self.proc is None and not self.start():
            return
        if self.proc.poll() is not None:
            if not self._failure_reported:
                print(
                    f"HLS WARNING: FFmpeg exited early rc={self.proc.returncode}; HLS disabled.",
                    file=sys.stderr, flush=True,
                )
                self._failure_reported = True
            self.failed = True
            return
        try:
            self.q.put_nowait(payload)
            self.bytes_queued += len(payload)
            self.queue_highwater = max(self.queue_highwater, self.q.qsize())
        except queue.Full:
            # Do not block or silently drop reference frames:
            # Preserve the session/.h265 capture and disable only HLS.
            self.failed = True
            print(
                "HLS WARNING: FFmpeg cannot keep up (queue full); HLS disabled to avoid blocking D102.",
                file=sys.stderr, flush=True,
            )

    def close(self) -> None:
        if self.proc is None:
            return
        if self.writer and self.writer.is_alive():
            try:
                self.q.put(None, timeout=1.0)
            except queue.Full:
                pass
            self.writer.join(timeout=5.0)
        try:
            rc = self.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                rc = self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                rc = self.proc.wait()
        print(
            f"HLS FINAL: queued={self.bytes_queued} written={self.bytes_written} "
            f"queue_highwater={self.queue_highwater}/256 ffmpeg_rc={rc} dir={self.out_dir}",
            file=sys.stderr, flush=True,
        )
        self.proc = None


class LiveHxvfExtractor:
    """Reensambla D102 y extrae HXVF/xV!C de forma incremental."""

    MAGIC_VIDEO = b"HXVF"
    MAGIC_AUDIO = b"xV!C"
    MAX_RECORD = 8 * 1024 * 1024

    def __init__(self, hevc_path: str | None, raw_path: str | None, key: bytes, aes_decrypt, hls_sink: FfmpegHlsSink | None = None):
        self.buffer = bytearray()
        self.hevc = open(hevc_path, "wb") if hevc_path else None
        self.raw = open(raw_path, "wb") if raw_path else None
        self.key = key
        self.aes_decrypt = aes_decrypt
        self.hls_sink = hls_sink
        self.video_frames = 0
        self.audio_records = 0
        self.resyncs = 0
        self.bytes_hevc = 0
        self.first_video_reported = False
        self.output_synced = False
        self.frames_before_sync = 0
        self.first_sync_nals: list[int] = []

    def reset_on_gap(self) -> None:
        # If a fragment is lost, the current record becomes unusable and
        # even if the next HXVF is recovered, later P-frames may
        # subsequent HEVC pictures may depend on the lost reference. Wait again for a
        # acceso aleatorio limpio VPS/SPS/PPS+IRAP antes de alimentar FFmpeg.
        if self.buffer:
            self.buffer = self.buffer[-3:]
        self.output_synced = False
        self.resyncs += 1

    def feed(self, chunk: bytes) -> None:
        if self.raw:
            self.raw.write(chunk)
        self.buffer.extend(chunk)
        self._parse()

    def _next_magic(self, start: int = 0) -> int:
        a = self.buffer.find(self.MAGIC_VIDEO, start)
        b = self.buffer.find(self.MAGIC_AUDIO, start)
        candidates = [x for x in (a, b) if x >= 0]
        return min(candidates) if candidates else -1

    def _parse(self) -> None:
        while True:
            if len(self.buffer) < 16:
                return

            magic = bytes(self.buffer[:4])
            if magic not in (self.MAGIC_VIDEO, self.MAGIC_AUDIO):
                idx = self._next_magic(1)
                if idx < 0:
                    # Keep 3 bytes to detect a magic value split across datagrams.
                    if len(self.buffer) > 3:
                        del self.buffer[:-3]
                    return
                del self.buffer[:idx]
                self.resyncs += 1
                continue

            length, timestamp, frame_type = struct.unpack_from("<III", self.buffer, 4)
            if length > self.MAX_RECORD:
                del self.buffer[0]
                self.resyncs += 1
                continue

            total = 16 + length
            if len(self.buffer) < total:
                return

            payload = bytes(self.buffer[16:total])
            del self.buffer[:total]

            if magic == self.MAGIC_AUDIO:
                self.audio_records += 1
                continue

            encrypted = frame_type == 1 and not payload.startswith(b"\x00\x00\x00\x01")
            if encrypted:
                if self.aes_decrypt is None:
                    print(
                        "VIDEO WARNING: encrypted I-frame received but no AES library is available; install cryptography.",
                        file=sys.stderr, flush=True,
                    )
                else:
                    payload = decrypt_video_prefix_96(payload, self.key, self.aes_decrypt)

            nal_types = annexb_nal_types(payload)
            annexb = bool(nal_types)

            # Do not feed orphan P-frames to FFmpeg. Wait for a clean random-access
            # aleatorio completo que incluya VPS/SPS/PPS + IRAP. Esto hace que
            # make the .h265 decodable even when capture starts
            # in the middle of a GOP or the first I-frame is lost.
            if not self.output_synced:
                if is_clean_irap_start(nal_types):
                    self.output_synced = True
                    self.first_sync_nals = nal_types
                    print(
                        f"*** HEVC SYNC *** timestamp={timestamp} type={frame_type} "
                        f"payload={len(payload)} NAL={nal_types}",
                        file=sys.stderr, flush=True,
                    )
                else:
                    self.frames_before_sync += 1
                    if self.frames_before_sync == 1 or self.frames_before_sync % 25 == 0:
                        print(
                            f"VIDEO: waiting for VPS/SPS/PPS+IRAP; dropped={self.frames_before_sync} "
                            f"type={frame_type} NAL={nal_types[:12]}",
                            file=sys.stderr, flush=True,
                        )
                    continue

            if self.hevc:
                self.hevc.write(payload)
            if self.hls_sink:
                self.hls_sink.write(payload)
            self.video_frames += 1
            self.bytes_hevc += len(payload)

            if not self.first_video_reported:
                print(
                    f"*** HEVC FRAME EXTRACTED *** frame={self.video_frames} type={frame_type} "
                    f"timestamp={timestamp} payload={len(payload)} AnnexB={int(annexb)} NAL={nal_types}",
                    file=sys.stderr, flush=True,
                )
                self.first_video_reported = True
            elif self.video_frames % 30 == 0:
                print(
                    f"VIDEO: frames={self.video_frames} HEVC={self.bytes_hevc} bytes "
                    f"audio={self.audio_records} resyncs={self.resyncs} "
                    f"pre_sync={self.frames_before_sync}",
                    file=sys.stderr, flush=True,
                )

    def close(self) -> None:
        if self.hevc:
            self.hevc.close()
            self.hevc = None
        if self.raw:
            self.raw.close()
            self.raw = None
PUNCH_ACK = b"\xf1\xe1\x00\x00"
SESSION_READY = b"\xf1\xf0\x00\x00"


def route_local_ip(camera_ip: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((camera_ip, 9))
        return probe.getsockname()[0]
    finally:
        probe.close()


def configure_socket(sock: socket.socket) -> bool:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # En Windows, un ICMP Port Unreachable puede aparecer como
    # ConnectionResetError/WinError 10054 on the next recvfrom().
    # Do not use SIO_UDP_CONNRESET here: socket.ioctl() does not accept that command
    # on every Python version. The receive loop treats this as non-fatal.
    # Windows defines IP_DONTFRAGMENT as 14, but Python does not always expose
    # constant. v0.11 did not apply it and the PCAP showed DF=0.
    ip_dontfragment = getattr(socket, "IP_DONTFRAGMENT", 14)
    df_enabled = False
    try:
        sock.setsockopt(socket.IPPROTO_IP, ip_dontfragment, 1)
        df_enabled = bool(sock.getsockopt(socket.IPPROTO_IP, ip_dontfragment))
    except OSError:
        df_enabled = False
    sock.setblocking(False)
    return df_enabled


def make_consecutive_sockets(local_ip: str, base_port: int = 0):
    """Create three consecutive sockets: wake, primary PPPP, and secondary PPPP."""
    last_error: OSError | None = None
    for _ in range(128):
        wake = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        primary = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        secondary = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            df0 = configure_socket(wake)
            df1 = configure_socket(primary)
            df2 = configure_socket(secondary)
            wake.bind((local_ip, base_port))
            p0 = wake.getsockname()[1]
            if p0 >= 65534:
                raise OSError("Unable to reserve three consecutive ports")
            primary.bind((local_ip, p0 + 1))
            secondary.bind((local_ip, p0 + 2))
            return wake, primary, secondary, df0, df1, df2
        except OSError as exc:
            last_error = exc
            wake.close(); primary.close(); secondary.close()
            if base_port:
                break
    raise last_error or OSError("No fue posible crear sockets consecutivos")


@dataclass
class State:
    peer: tuple[str, int] | None = None
    f141: int = 0
    f142: int = 0
    punches: int = 0
    f1e1: int = 0
    f1f0: int = 0
    rx_total: int = 0
    first_hello_at: float | None = None
    first_punch_at: float | None = None
    bootstrap_sent: int = 0
    bootstrap_acked: int = 0
    data_rx: int = 0
    data_ack_tx: int = 0
    acked_sequences: set[int] | None = None
    app_commands_sent: set[int] | None = None
    camera_commands: list[str] | None = None

    def __post_init__(self):
        if self.acked_sequences is None:
            self.acked_sequences = set()
        if self.app_commands_sent is None:
            self.app_commands_sent = set()
        if self.camera_commands is None:
            self.camera_commands = []


def log_rx(label: str, sock: socket.socket, data: bytes, peer: tuple[str, int]) -> None:
    local = sock.getsockname()
    print(
        f"RX[{label}] {peer[0]}:{peer[1]} -> {local[0]}:{local[1]} "
        f"{packet_name(data)} len={len(data)} {data[:128].hex()}",
        file=sys.stderr,
        flush=True,
    )


def send_logged(label: str, sock: socket.socket, data: bytes, peer: tuple[str, int]) -> None:
    sock.sendto(data, peer)
    print(
        f"TX[{label}] {packet_name(data)} {sock.getsockname()[0]}:{sock.getsockname()[1]} "
        f"-> {peer[0]}:{peer[1]} len={len(data)} {data.hex()}",
        file=sys.stderr,
        flush=True,
    )


def send_discovery_burst(
    primary: socket.socket,
    secondary: socket.socket,
    target: tuple[str, int],
    gap_ms: float = 0.0,
    middle_ms: float = 0.0,
) -> None:
    # Offline Genbolt capture: all four datagrams are sent within 0.2-0.4 ms.
    # Do not add tens-of-milliseconds sleeps: use consecutive sendto calls.
    secondary.sendto(DISCOVER, target)
    secondary.sendto(DISCOVER, target)
    primary.sendto(DISCOVER, target)
    primary.sendto(DISCOVER, target)



def load_private_packet(private_dir: Path, name: str, expected_seq: int | None = None) -> bytes:
    """Load device-specific protocol material from an external file.

    Public builds intentionally do not embed captured authentication/session
    packets. Keep these files outside the repository and executable.
    """
    path = private_dir / name
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Missing private protocol material: {path}") from exc
    if len(data) < 8 or not data.startswith(b"\xf1\xd0"):
        raise RuntimeError(f"Invalid private F1D0 packet: {path}")
    if expected_seq is not None and int.from_bytes(data[6:8], "big") != expected_seq:
        raise RuntimeError(f"Unexpected sequence number in {path}; expected {expected_seq}")
    return data


def load_bootstrap_packets(private_dir: Path) -> list[bytes]:
    packets = [
        load_private_packet(private_dir, "bootstrap_f1d0_0000.bin", 0),
        load_private_packet(private_dir, "bootstrap_f1d0_0001.bin", 1),
    ]
    for name, data in zip(("bootstrap_f1d0_0000.bin", "bootstrap_f1d0_0001.bin"), packets):
        if len(data) != 720:
            raise RuntimeError(f"Invalid bootstrap resource {name}: {len(data)} bytes; expected 720")
    return packets


def load_late_session_packets(private_dir: Path) -> tuple[bytes, bytes, bytes]:
    """Load seq13..15 packets kept private because they contain captured opaque data."""
    return (
        load_private_packet(private_dir, "seq13_f1d0.bin", 13),
        load_private_packet(private_dir, "seq14_f1d0.bin", 14),
        load_private_packet(private_dir, "seq15_f1d0.bin", 15),
    )


def f1d0_sequence(data: bytes) -> int | None:
    if len(data) < 8 or data[:2] != b"\xf1\xd0":
        return None
    return int.from_bytes(data[6:8], "big")


def make_f1d1_ack(data: bytes) -> bytes | None:
    seq = f1d0_sequence(data)
    if seq is None:
        return None
    # Observed format: F1D1, payload 6, session/channel, count=1, seq16.
    return b"\xf1\xd1\x00\x06" + data[4:6] + b"\x00\x01" + seq.to_bytes(2, "big")



def make_short_f1d0(seq: int, command_bytes: bytes) -> bytes:
    """Build the 32-byte short F1D0 observed after bootstrap.

    command_bytes must contain exactly the four command-field bytes as they
    appear on the wire (for example 05 f0 00 00).
    """
    if not 0 <= seq <= 0xFFFF:
        raise ValueError("seq out of range")
    if len(command_bytes) != 4:
        raise ValueError("command_bytes must be exactly 4 bytes")
    payload = (
        b"\xd1\x00" + seq.to_bytes(2, "big") +
        b"\x99\x99\x99\x99" +
        b"\x00\x00\x00\x00" +
        command_bytes +
        b"\x00" * 12
    )
    return b"\xf1\xd0" + len(payload).to_bytes(2, "big") + payload


def parse_f1d1_sequences(data: bytes) -> list[int]:
    """Extract all sequence numbers from an F1D1 ACK, including grouped ACKs."""
    if len(data) < 8 or data[:2] != b"\xf1\xd1":
        return []
    count = int.from_bytes(data[6:8], "big")
    available = max(0, (len(data) - 8) // 2)
    count = min(count, available)
    return [int.from_bytes(data[8 + 2*i:10 + 2*i], "big") for i in range(count)]


def f1d0_command_bytes(data: bytes) -> bytes | None:
    """Return the four-byte command field from a HiChip F1D0 packet."""
    if len(data) < 20 or data[:2] != b"\xf1\xd0":
        return None
    return data[16:20]


class SessionDump:
    """Length-prefixed dump that preserves each datagram unambiguously."""
    def __init__(self, path: str | None):
        self.file = open(path, "wb") if path else None
        if self.file:
            self.file.write(b"HCF1D0\x01")
            self.file.flush()

    def write(self, direction: int, data: bytes) -> None:
        if not self.file:
            return
        # timestamp_ns, direction (0=RX,1=TX), length, datagram
        self.file.write(struct.pack(">QBI", time.time_ns(), direction, len(data)))
        self.file.write(data)

    def close(self) -> None:
        if self.file:
            self.file.close()
            self.file = None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="HiChip LAN PPPP client 0.22.0: public release with external private material."
    )
    parser.add_argument("--camera-ip", required=True, help="Camera IPv4 address on the LAN.")
    parser.add_argument("--local-ip", help="Local LAN IPv4 address; auto-detected when omitted.")
    parser.add_argument("--base-port", type=int, default=0, help="Optional fixed primary UDP port.")
    parser.add_argument("--discover-port", type=int, default=32108)
    parser.add_argument("--wake-port", type=int, default=50000)
    parser.add_argument("--wake-mac", default=os.environ.get("HICHIP_WAKE_MAC"), help="Camera MAC address used by the wake packet. Can also be set with HICHIP_WAKE_MAC.")
    parser.add_argument("--wake-interval", type=float, default=0.250, help="UDP/50000 magic-packet interval.")
    parser.add_argument("--broadcast", default="255.255.255.255", help="Broadcast address; Genbolt uses 255.255.255.255.")
    parser.add_argument("--seconds", type=float, default=0.0, help="Maximum total runtime in seconds; 0 = unlimited (default).")
    parser.add_argument("--burst-interval", type=float, default=1.10, help="Seconds between F130 bursts.")
    parser.add_argument("--pair-lifetime", type=float, default=20.0, help="Lifetime of each PPPP socket pair before recreating it.")
    parser.add_argument("--pair-pause", type=float, default=2.10, help="Pause between attempts with new PPPP socket pairs.")
    parser.add_argument("--gap-ms", type=float, default=0.0, help="Compatibility option; v0.14 does not add a delay.")
    parser.add_argument("--middle-ms", type=float, default=0.0, help="Compatibility option; v0.14 does not add a delay.")
    parser.add_argument(
        "--post-hello-seconds", type=float, default=30.0,
        help="Minimum continuation time after the first F141."
    )
    parser.add_argument(
        "--bootstrap-delay", type=float, default=0.80,
        help="Delay after the first F1E0 before sending the first F1D0."
    )
    parser.add_argument(
        "--no-bootstrap", action="store_true",
        help="Complete PPPP only; do not replay the reference F1D0 packets."
    )
    parser.add_argument(
        "--session-dump", default="",
        help="Binary F1D0/F1D1 dump; empty by default to avoid disk growth in service mode."
    )
    parser.add_argument(
        "--stage2-timeout", type=float, default=3.0,
        help="After ACKs for seq 2-4, maximum wait for the 05F0 response before sending seq 5-6."
    )
    parser.add_argument(
        "--hevc-out", default="",
        help="Debug HEVC Annex-B output; empty by default to avoid unlimited disk growth."
    )
    parser.add_argument(
        "--d102-out", default="",
        help="Raw D102 debug output; empty by default to avoid unlimited disk growth."
    )
    parser.add_argument(
        "--video-key", default=os.environ.get("HICHIP_VIDEO_KEY"),
        help="AES-128 video key as 32 hexadecimal digits. Can also be set with HICHIP_VIDEO_KEY."
    )
    parser.add_argument(
        "--private-dir", default=os.environ.get("HICHIP_PRIVATE_DIR", "private_material"),
        help="Directory containing device-specific captured F1D0 material. Default: private_material."
    )
    parser.add_argument(
        "--hls-dir", default="hls",
        help="Live HLS directory; empty to disable. Default: hls."
    )
    parser.add_argument(
        "--ffmpeg", default="ffmpeg",
        help="FFmpeg executable or full path. Default: ffmpeg (PATH or executable directory)."
    )
    parser.add_argument(
        "--video-fps", type=float, default=12.5,
        help="HEVC input and HLS output frame rate. Default: 12.5 fps (observed 80 ms/frame)."
    )
    parser.add_argument(
        "--hls-time", type=float, default=2.0,
        help="Target HLS segment duration; an H.264 IDR is forced at each boundary and FFmpeg is fed asynchronously."
    )
    parser.add_argument(
        "--hls-list-size", type=int, default=6,
        help="Number of segments kept in the live HLS playlist."
    )
    parser.add_argument(
        "--hls-http-port", type=int, default=8080,
        help="Integrated HLS HTTP server port; 0 to disable. Default: 8080."
    )
    parser.add_argument(
        "--hls-http-bind", default="0.0.0.0",
        help="HLS HTTP bind address. Default: 0.0.0.0 for LAN access."
    )
    parser.add_argument(
        "--stream-watchdog", type=float, default=30.0,
        help="After video starts, exit with rc=20 if no D102 arrives for N seconds so a service manager can restart it. 0=disable."
    )
    parser.add_argument(
        "--log-file", default="logs/hichip_streamer.log",
        help="Rotating log file. Empty to disable. Default: logs/hichip_streamer.log."
    )
    parser.add_argument(
        "--log-max-mb", type=float, default=5.0,
        help="Maximum size of each log file before rotation. Default: 5 MB."
    )
    parser.add_argument(
        "--log-backups", type=int, default=3,
        help="Number of rotated log files to keep. Default: 3."
    )
    parser.add_argument(
        "--quiet-console", action="store_true",
        help="Do not mirror logs to the console; useful when running under NSSM."
    )
    args = parser.parse_args(argv)

    original_stderr = sys.stderr
    rotating_log = RotatingLogWriter(
        args.log_file or None,
        int(max(0.1, args.log_max_mb) * 1024 * 1024),
        max(1, args.log_backups),
        None if args.quiet_console else original_stderr,
    )
    if args.log_file:
        sys.stderr = rotating_log
        print("\n=== HiChip Streamer v0.22.0 START ===", file=sys.stderr, flush=True)
        print(f"PID={os.getpid()} cwd={Path.cwd()}", file=sys.stderr, flush=True)

    if not args.video_key:
        print("Missing --video-key (or HICHIP_VIDEO_KEY).", file=sys.stderr)
        return 2
    if not args.wake_mac:
        print("Missing --wake-mac (or HICHIP_WAKE_MAC).", file=sys.stderr)
        return 2
    try:
        video_key = bytes.fromhex(args.video_key)
        if len(video_key) != 16:
            raise ValueError
    except ValueError:
        print("--video-key must be a 32-hex-digit AES-128 key.", file=sys.stderr)
        return 2
    aes_decrypt = load_aes_decryptor()
    hls = FfmpegHlsSink(
        args.ffmpeg, args.hls_dir or None, args.video_fps, args.hls_time, max(1, args.hls_list_size)
    )
    hls_http = HlsHttpServer(args.hls_dir or None, args.hls_http_bind, args.hls_http_port)
    hls_http.start()
    video = LiveHxvfExtractor(
        args.hevc_out or None, args.d102_out or None, video_key, aes_decrypt, hls_sink=hls
    )
    if args.hevc_out:
        print(f"HEVC OUT: {Path(args.hevc_out).resolve()}", file=sys.stderr, flush=True)
    if args.d102_out:
        print(f"D102 RAW: {Path(args.d102_out).resolve()}", file=sys.stderr, flush=True)
    last_d102_seq: int | None = None
    d102_duplicates = 0
    d102_stale = 0
    d102_gaps = 0
    d102_lost = 0
    first_d102_at: float | None = None
    last_d102_at: float | None = None

    route_ip = route_local_ip(args.camera_ip)
    local_ip = args.local_ip or route_ip
    if local_ip.split(".")[:3] != args.camera_ip.split(".")[:3]:
        print(
            f"WARNING: local interface {local_ip} and camera {args.camera_ip} do not appear to be on the same /24.",
            file=sys.stderr,
        )

    # The wake socket remains fixed. The PPPP pair is recreated every ~20 s,
    # matching the observed offline Genbolt capture.
    try:
        wake, initial_primary, initial_secondary, df_wake, df_primary, df_secondary = make_consecutive_sockets(local_ip, args.base_port)
    except OSError as exc:
        print(f"Error preparando sockets: {exc}", file=sys.stderr)
        return 2

    primary = initial_primary
    secondary = initial_secondary
    directed_broadcast = args.broadcast
    target = (directed_broadcast, args.discover_port)
    wake_target = (directed_broadcast, args.wake_port)
    try:
        wake_mac = bytes.fromhex(args.wake_mac.replace(":", "").replace("-", ""))
        if len(wake_mac) != 6:
            raise ValueError
    except ValueError:
        print("--wake-mac must contain a 6-byte MAC address.", file=sys.stderr)
        wake.close(); primary.close(); secondary.close()
        return 2
    wake_packet = b"\xff" * 6 + wake_mac * 16 + b"\x00" * 14

    state = State()
    private_dir = Path(args.private_dir).resolve()
    try:
        bootstrap_packets = load_bootstrap_packets(private_dir)
        seq13_packet, seq14_packet, seq15_packet = load_late_session_packets(private_dir)
    except RuntimeError as exc:
        print(f"PRIVATE MATERIAL ERROR: {exc}", file=sys.stderr)
        return 2
    short_commands = {
        2: make_short_f1d0(2, bytes.fromhex("05f00000")),
        3: make_short_f1d0(3, bytes.fromhex("17410000")),
        4: make_short_f1d0(4, bytes.fromhex("06910000")),
        5: make_short_f1d0(5, bytes.fromhex("68410000")),
        6: make_short_f1d0(6, bytes.fromhex("3c410000")),
        # Stage 3 observed byte-for-byte in the Genbolt capture.
        7: make_short_f1d0(7, bytes.fromhex("19480000")),
        8: make_short_f1d0(8, bytes.fromhex("46000100")),
        9: make_short_f1d0(9, bytes.fromhex("14710000")),
        10: make_short_f1d0(10, bytes.fromhex("5e410000")),
        11: make_short_f1d0(11, bytes.fromhex("12000100")),
        12: make_short_f1d0(12, bytes.fromhex("1c000100")),
    }
    dump = SessionDump(args.session_dump or None)
    stage1_acked_at: float | None = None
    stage4_sent = False
    stage5_sent = False
    stage6_sent = False
    camera_05f0_seen = False
    stage3_sent = False
    started = time.monotonic()
    deadline = float("inf") if args.seconds <= 0 else started + max(1.0, args.seconds)
    next_wake = started
    next_burst = started + 0.070
    pair_started = started
    pair_generation = 1
    rotating_until: float | None = None
    burst = 0
    bursts_this_pair = 0

    def socket_labels():
        return {wake: "wake", primary: "primary", secondary: "secondary"}

    print(f"Route to camera: {route_ip} -> {args.camera_ip}", file=sys.stderr)
    print(
        f"Sockets: persistent wake={wake.getsockname()} PPPP pair#{pair_generation}: "
        f"primary={primary.getsockname()} secondary={secondary.getsockname()} "
        f"DF=({int(df_wake)},{int(df_primary)},{int(df_secondary)})", file=sys.stderr
    )
    print(
        f"Wake: {args.wake_mac} every {args.wake_interval:.3f}s -> {directed_broadcast}:{args.wake_port}; "
        f"PPPP: burst every {args.burst_interval:.2f}s, new pair every {args.pair_lifetime:.1f}s "
        f"after a {args.pair_pause:.1f}s pause -> {directed_broadcast}:{args.discover_port}",
        file=sys.stderr,
    )

    print(
        f"SERVICE: runtime={'unlimited' if args.seconds <= 0 else f'{args.seconds:g}s'}; "
        f"watchdog D102={args.stream_watchdog:g}s; HTTP bind={args.hls_http_bind}:{args.hls_http_port}; "
        f"log={Path(args.log_file).resolve() if args.log_file else 'desactivado'}",
        file=sys.stderr, flush=True,
    )

    def create_new_pair():
        nonlocal primary, secondary, df_primary, df_secondary, pair_generation, pair_started, next_burst, bursts_this_pair
        # Create three sockets and discard the first to obtain two consecutive ports
        # without changing the persistent wake socket.
        dummy, new_primary, new_secondary, _, new_df1, new_df2 = make_consecutive_sockets(local_ip, 0)
        dummy.close()
        primary = new_primary
        secondary = new_secondary
        df_primary, df_secondary = new_df1, new_df2
        pair_generation += 1
        pair_started = time.monotonic()
        next_burst = pair_started + 0.070
        bursts_this_pair = 0
        print(
            f"NEW PPPP PAIR#{pair_generation}: primary={primary.getsockname()} "
            f"secondary={secondary.getsockname()} DF=({int(df_primary)},{int(df_secondary)})",
            file=sys.stderr, flush=True,
        )

    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if (
                args.stream_watchdog > 0
                and first_d102_at is not None
                and last_d102_at is not None
                and now - last_d102_at >= args.stream_watchdog
            ):
                print(
                    f"WATCHDOG: no D102 for {now-last_d102_at:.1f}s after video started; "
                    "exiting with rc=20 so the service manager can restart the process.",
                    file=sys.stderr, flush=True,
                )
                return 20
            if state.peer is None and now >= next_wake:
                wake.sendto(wake_packet, wake_target)
                next_wake += max(0.01, args.wake_interval)
                if next_wake < now:
                    next_wake = now + max(0.01, args.wake_interval)

            if state.peer is None and rotating_until is None and now - pair_started >= args.pair_lifetime:
                print(
                    f"PPPP pair#{pair_generation} expired after {bursts_this_pair} bursts; "
                    f"recreando en {args.pair_pause:.1f}s.", file=sys.stderr, flush=True,
                )
                primary.close(); secondary.close()
                rotating_until = now + max(0.0, args.pair_pause)

            if state.peer is None and rotating_until is not None and now >= rotating_until:
                create_new_pair()
                rotating_until = None

            if state.peer is None and rotating_until is None and now >= next_burst:
                burst += 1
                bursts_this_pair += 1
                send_discovery_burst(primary, secondary, target, args.gap_ms, args.middle_ms)
                print(
                    f"TX F130 pair#{pair_generation} burst #{bursts_this_pair} (total {burst}): "
                    f"secondary={secondary.getsockname()[1]} x2, primary={primary.getsockname()[1]} x2",
                    file=sys.stderr, flush=True,
                )
                next_burst = time.monotonic() + max(0.1, args.burst_interval)

            if (
                state.peer is not None
                and state.first_punch_at is not None
                and not args.no_bootstrap
                and state.bootstrap_sent == 0
                and now - state.first_punch_at >= max(0.0, args.bootstrap_delay)
            ):
                send_logged("primary", primary, bootstrap_packets[0], state.peer)
                dump.write(1, bootstrap_packets[0])
                state.bootstrap_sent = 1
                print(
                    "BOOTSTRAP: sent 720-byte F1D0 seq=0; waiting for F1D1.",
                    file=sys.stderr, flush=True,
                )

            if (
                state.peer is not None
                and {2, 3, 4}.issubset(state.acked_sequences)
                and not {5, 6}.intersection(state.app_commands_sent)
                and (
                    camera_05f0_seen
                    or (stage1_acked_at is not None and now - stage1_acked_at >= max(0.0, args.stage2_timeout))
                )
            ):
                reason = "05F0 response" if camera_05f0_seen else "05F0 wait timeout"
                print(f"STAGE2: {reason}; sending 6841 and 3C41.", file=sys.stderr, flush=True)
                for seq in (5, 6):
                    send_logged("primary", primary, short_commands[seq], state.peer)
                    dump.write(1, short_commands[seq])
                    state.app_commands_sent.add(seq)
                deadline = max(deadline, time.monotonic() + 15.0)

            sockets = [wake]
            if rotating_until is None:
                sockets.extend([primary, secondary])
            labels = socket_labels()
            timeout = 0.05
            ready, _, _ = select.select(sockets, [], [], timeout)
            for sock in ready:
                while True:
                    try:
                        data, peer = sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    except ConnectionResetError as exc:
                        # Windows reports an ICMP Port Unreachable here as
                        # WSAECONNRESET. Do not close or rotate the socket; keep going.
                        print(
                            f"non-fatal UDP 10054 on {labels.get(sock, '?')} "
                            f"{sock.getsockname()}: {exc}",
                            file=sys.stderr, flush=True,
                        )
                        break
                    except OSError as exc:
                        if getattr(exc, "winerror", None) == 10054:
                            print(
                                f"non-fatal UDP 10054 on {labels.get(sock, '?')} "
                                f"{sock.getsockname()}: {exc}",
                                file=sys.stderr, flush=True,
                            )
                            break
                        raise
                    label = labels.get(sock, "?")
                    if peer[0] == local_ip and (data == DISCOVER or data == wake_packet):
                        continue
                    is_d102 = len(data) >= 8 and data[:2] == b"\xf1\xd0" and data[4:6] == b"\xd1\x02"
                    # Fast-path multimedia: imprimir 128 bytes de cada D102 a consola
                    # blocked the receive loop long enough to lose UDP packets.
                    if not is_d102:
                        log_rx(label, sock, data, peer)
                    state.rx_total += 1
                    if peer[0] != args.camera_ip:
                        continue
                    if data[:2] == b"\xf1A":
                        state.f141 += 1
                        if state.peer is None:
                            state.peer = peer
                            state.first_hello_at = time.monotonic()
                            deadline = max(deadline, time.monotonic() + args.post_hello_seconds)
                            print(
                                f"CAMERA FOUND: {peer[0]}:{peer[1]} with pair#{pair_generation} "
                                f"after {time.monotonic()-started:.3f}s and {burst} bursts.",
                                file=sys.stderr,
                            )
                        reply = b"\xf1B" + data[2:]
                        for out_label, out_sock in (("primary", primary), ("secondary", secondary)):
                            send_logged(out_label, out_sock, reply, peer)
                            state.f142 += 1
                        continue
                    if state.peer is not None and peer != state.peer:
                        continue
                    if data[:2] == b"\xf1\xe0":
                        state.punches += 1
                        if state.first_punch_at is None:
                            state.first_punch_at = time.monotonic()
                            print("PPPP: first F1E0 received; starting stabilization window.", file=sys.stderr)
                        send_logged("primary", primary, PUNCH_ACK, peer); state.f1e1 += 1
                        send_logged("secondary", secondary, SESSION_READY, peer); state.f1f0 += 1
                        continue
                    if data[:2] == b"\xf1\xd1":
                        dump.write(0, data)
                        acked = parse_f1d1_sequences(data)
                        state.acked_sequences.update(acked)
                        print(
                            f"RX DATA_ACK seqs={acked} len={len(data)} {data.hex()}",
                            file=sys.stderr, flush=True,
                        )
                        if state.bootstrap_sent == 1 and 0 in acked:
                            state.bootstrap_acked = max(state.bootstrap_acked, 1)
                            send_logged("primary", primary, bootstrap_packets[1], peer)
                            dump.write(1, bootstrap_packets[1])
                            state.bootstrap_sent = 2
                            print("BOOTSTRAP: ACK seq=0; sent 720-byte F1D0 seq=1.", file=sys.stderr)
                        if state.bootstrap_sent >= 2 and 1 in acked and state.bootstrap_acked < 2:
                            state.bootstrap_acked = 2
                            print(
                                "BOOTSTRAP OK: camera confirmed seq 0 and 1. Sending commands 05F0, 1741, and 0691.",
                                file=sys.stderr, flush=True,
                            )
                            for seq in (2, 3, 4):
                                send_logged("primary", primary, short_commands[seq], peer)
                                dump.write(1, short_commands[seq])
                                state.app_commands_sent.add(seq)
                            deadline = max(deadline, time.monotonic() + 20.0)
                        if {2, 3, 4}.issubset(state.acked_sequences) and stage1_acked_at is None:
                            stage1_acked_at = time.monotonic()
                            print("STAGE1 ACK: seq 2,3,4 confirmed; waiting for 05F0 response.", file=sys.stderr)
                        if 5 in state.acked_sequences and 6 in state.acked_sequences:
                            print(
                                "BASE SUCCESS: camera confirmed seq 2..6; HiChip command layer is active over PPPP LAN.",
                                file=sys.stderr, flush=True,
                            )
                            deadline = max(deadline, time.monotonic() + 10.0)
                        continue
                    if data[:2] == b"\xf1\xd0":
                        dump.write(0, data)
                        state.data_rx += 1
                        ack = make_f1d1_ack(data)
                        if ack is not None:
                            if is_d102:
                                # ACK as quickly as possible without synchronous logging.
                                primary.sendto(ack, peer)
                            else:
                                send_logged("primary", primary, ack, peer)
                            dump.write(1, ack)
                            state.data_ack_tx += 1
                        seq = f1d0_sequence(data)
                        command = f1d0_command_bytes(data)
                        command_hex = command.hex() if command is not None else "----"
                        if command is not None and not is_d102:
                            state.camera_commands.append(command_hex)
                        if not is_d102:
                            print(
                                f"CAMERA DATA: seq={seq} cmd={command_hex} len={len(data)}; ACK sent.",
                                file=sys.stderr, flush=True,
                            )
                        if command == bytes.fromhex("05f00000"):
                            camera_05f0_seen = True
                            print("RX 05F0: session response/capabilities received.", file=sys.stderr)
                        if command == bytes.fromhex("3c410000") and not stage3_sent:
                            print(
                                "STAGE3: 3C41 response received and ACKed; sending observed Genbolt sequence 7..12 "
                                "[1948,460001,1471,5E41,120001,1C0001].",
                                file=sys.stderr, flush=True,
                            )
                            for out_seq in range(7, 13):
                                send_logged("primary", primary, short_commands[out_seq], peer)
                                dump.write(1, short_commands[out_seq])
                                state.app_commands_sent.add(out_seq)
                            stage3_sent = True
                            deadline = max(deadline, time.monotonic() + 20.0)
                        if command == bytes.fromhex("1c000100") and not stage4_sent:
                            seq13 = seq13_packet
                            print(
                                "STAGE4: 1C0001 response received and ACKed; sending external seq13 02F0 packet.",
                                file=sys.stderr, flush=True,
                            )
                            send_logged("primary", primary, seq13, peer)
                            dump.write(1, seq13)
                            state.app_commands_sent.add(13)
                            stage4_sent = True
                            deadline = max(deadline, time.monotonic() + 30.0)
                        if command == bytes.fromhex("02f00000") and seq == 13 and not stage5_sent:
                            seq14 = seq14_packet
                            print(
                                "STAGE5: 02F0 seq13 response received and ACKed; sending external seq14 4132 packet "
                                "using the external observed 77-byte Genbolt packet.",
                                file=sys.stderr, flush=True,
                            )
                            send_logged("primary", primary, seq14, peer)
                            dump.write(1, seq14)
                            state.app_commands_sent.add(14)
                            stage5_sent = True
                            deadline = max(deadline, time.monotonic() + 30.0)
                        if command == bytes.fromhex("32410000") and seq == 14 and not stage6_sent:
                            seq15 = seq15_packet
                            print(
                                "STAGE6: 3241 seq14 response received and ACKed; sending external seq15 1001 packet "
                                "from private protocol material. In observed captures, D102 starts immediately afterward.",
                                file=sys.stderr, flush=True,
                            )
                            send_logged("primary", primary, seq15, peer)
                            dump.write(1, seq15)
                            state.app_commands_sent.add(15)
                            stage6_sent = True
                            deadline = max(deadline, time.monotonic() + 45.0)
                        # Media channel: strip the 8 PPPP bytes, order by sequence number, and
                        # feed the incremental HXVF reassembler.
                        if len(data) >= 8 and data[4:6] == b"\xd1\x02":
                            last_d102_at = time.monotonic()
                            if first_d102_at is None:
                                first_d102_at = last_d102_at
                                print("SERVICE: first D102 received; video watchdog armed.", file=sys.stderr, flush=True)
                            if seq is not None:
                                if last_d102_seq is not None:
                                    delta = (seq - last_d102_seq) & 0xFFFF
                                    expected = (last_d102_seq + 1) & 0xFFFF
                                    if delta == 0:
                                        d102_duplicates += 1
                                        print(
                                            f"D102 duplicado seq={seq}; ignorado.",
                                            file=sys.stderr, flush=True,
                                        )
                                        continue
                                    if delta >= 0x8000:
                                        # Old retransmission: the camera may resend packets
                                        # hundreds of datagrams later. They must never be reinserted
                                        # into the current byte stream.
                                        d102_stale += 1
                                        print(
                                            f"D102 late retransmission seq={seq} (current={last_d102_seq}); ignored.",
                                            file=sys.stderr, flush=True,
                                        )
                                        continue
                                    if delta > 1:
                                        missing = delta - 1
                                        d102_gaps += 1
                                        d102_lost += missing
                                        print(
                                            f"D102 WARNING: gap {last_d102_seq}->{seq} (expected {expected}); "
                                            f"{missing} packet(s) missing. Dropping partial HXVF frame.",
                                            file=sys.stderr, flush=True,
                                        )
                                        video.reset_on_gap()
                                last_d102_seq = seq
                            video.feed(data[8:])
                            if seq is not None and (seq & 0xFF) == 0:
                                print(
                                    f"D102: seq={seq} frames={video.video_frames} gaps={d102_gaps} "
                                    f"lost={d102_lost} stale={d102_stale}",
                                    file=sys.stderr, flush=True,
                                )
                        continue

        if state.peer is None:
            print(
                f"No F141 received after {pair_generation} pairs, {burst} bursts, and "
                f"{time.monotonic()-started:.1f}s.", file=sys.stderr,
            )
            return 3
        print(
            f"Handshake parcial: peer={state.peer} F141={state.f141} F142={state.f142} "
            f"PUNCH={state.punches} F1E1={state.f1e1} F1F0={state.f1f0} "
            f"BOOT={state.bootstrap_sent}/{state.bootstrap_acked} ACKED={sorted(state.acked_sequences)} "
            f"CMDS_RX={state.camera_commands} DATA_RX={state.data_rx} "
            f"DATA_ACK_TX={state.data_ack_tx} RX={state.rx_total}",
            file=sys.stderr,
        )
        return 5
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        return 130
    finally:
        print(
            f"VIDEO FINAL: frames={video.video_frames} HEVC={video.bytes_hevc} bytes "
            f"audio={video.audio_records} resyncs={video.resyncs} pre_sync={video.frames_before_sync} "
            f"d102_gaps={d102_gaps} d102_lost={d102_lost} "
            f"d102_dup={d102_duplicates} d102_stale={d102_stale}",
            file=sys.stderr, flush=True,
        )
        video.close()
        hls.close()
        hls_http.close()
        dump.close()
        wake.close()
        try: primary.close()
        except Exception: pass
        try: secondary.close()
        except Exception: pass
        if args.log_file:
            print("=== HiChip Streamer v0.22.0 STOP ===", file=sys.stderr, flush=True)
            sys.stderr = original_stderr
            rotating_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
