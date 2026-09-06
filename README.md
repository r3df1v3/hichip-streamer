# HiChip Streamer

Experimental LAN-only video streamer for selected HiChip/Genbolt cameras. It talks directly to the camera over the observed PPPP/HiChip protocol, reconstructs HXVF video records, decrypts the encrypted HEVC prefix, and optionally uses FFmpeg to publish an H.264/HLS stream.

> **Status:** v0.22.1. This maintenance release adds dynamic camera-IP rediscovery after DHCP address changes, while retaining the externalized device-specific configuration and captured session material introduced in v0.22.0. Device-specific captured authentication/session material is deliberately **not included** in the public tree.

## Why this project exists

The original deployment used the Android vendor application inside NOX, ADB screenshots, ImageMagick cropping, and SCP uploads just to obtain camera images. HiChip Streamer replaces that chain with direct LAN communication:

```text
Camera -> PPPP/HiChip -> HXVF -> HEVC -> FFmpeg -> H.264/HLS -> browser / reverse proxy
```

The tested camera produced HEVC at 2304x1296 and about 12.5 fps. The default HLS pipeline transcodes it to H.264 1280x720 at 12.5 fps with approximately two-second segments.

## What works

- LAN discovery and PPPP session establishment.
- Dynamic camera-IP rediscovery: `--camera-ip` is treated as a preferred address and a valid F141 reply from a new address can be adopted automatically after a restart/reconnect.
- HiChip command/session replay through the point where the D1/02 media channel starts.
- D102 sequencing, ACK handling, duplicate/late-packet handling, and HXVF reassembly.
- AES-128-ECB + XOR `0x3F` decryption of the encrypted 96-byte I-frame prefix observed on the tested device.
- Annex-B HEVC extraction.
- Asynchronous FFmpeg transcoding to H.264/HLS without blocking the UDP receive/ACK loop.
- Integrated HLS HTTP server, defaulting to `0.0.0.0:8080`.
- Rotating logs and a D102 watchdog suitable for a Windows service manager such as NSSM.
- FFmpeg discovery through `PATH` or next to the executable.

## Limited-disclosure public release

The working research build contained device-specific values and opaque packets captured from a real camera. Publishing those bytes would both expose private device material and disclose more of the authentication/session exchange than is necessary for the first public release.

v0.22.x therefore keeps the following outside the repository:

```text
private_material/
  bootstrap_f1d0_0000.bin
  bootstrap_f1d0_0001.bin
  seq13_f1d0.bin
  seq14_f1d0.bin
  seq15_f1d0.bin
```

The camera IP, wake MAC, and AES video key are also no longer compiled into the program. The video key and wake MAC may be supplied through command-line arguments or environment variables.

**Do not commit `private_material/`, camera credentials, device keys, packet captures, logs, Cloudflare tokens, or real camera UIDs.**

## Requirements

- Python 3.10+ recommended.
- `cryptography>=42`.
- FFmpeg for HLS output.
- Camera and streamer host on a LAN where the required UDP broadcasts can reach the camera.

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

## Running from source

Example using environment variables for secrets/device-specific values:

```cmd
set HICHIP_WAKE_MAC=AA:BB:CC:DD:EE:FF
set HICHIP_VIDEO_KEY=00112233445566778899aabbccddeeff
python hichip_client_launcher.py --camera-ip 192.168.1.50 --local-ip 192.168.1.20
```

Or pass them explicitly:

```cmd
python hichip_client_launcher.py ^
  --camera-ip 192.168.1.50 ^
  --local-ip 192.168.1.20 ^
  --wake-mac AA:BB:CC:DD:EE:FF ^
  --video-key 00112233445566778899aabbccddeeff ^
  --private-dir private_material
```

Passing the key on the command line can expose it through shell history or process listings. Environment variables or service-manager environment settings are preferable for long-running installations.

### Dynamic camera IP rediscovery

By default, `--camera-ip` is a **preferred address**, not a permanent lock. If the camera receives a different DHCP lease and the streamer reconnects, a valid LAN `F141` reply from the new address is adopted automatically. The log will report the configured and discovered addresses.

If your LAN contains multiple compatible HiChip cameras and you want to disable this behavior, add:

```text
--strict-camera-ip
```

With strict mode enabled, only `F141` replies from the configured `--camera-ip` are accepted. A DHCP reservation is still recommended for unattended deployments.

When HLS is enabled, the playlist is available at:

```text
http://STREAMER_IP:8080/index.m3u8
```

## Building on Windows

```cmd
build_windows.bat
```

The public build does not bundle `private_material`; keep that directory next to the executable or select another location with `--private-dir` / `HICHIP_PRIVATE_DIR`.

## Service deployment

The program runs indefinitely by default (`--seconds 0`). After the first D102 packet, the default watchdog exits with return code 20 if no D102 arrives for 30 seconds. A service manager can restart the process on exit.

Useful options include `--quiet-console`, `--log-file`, `--log-max-mb`, `--log-backups`, `--stream-watchdog`, `--hls-http-bind`, and `--hls-http-port`.

## Reverse proxy example

A simple Nginx route can expose the HLS server without transcoding on the proxy host:

```nginx
location /camera/ {
    proxy_pass http://STREAMER_IP:8080/;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    add_header Cache-Control "no-cache, no-store, must-revalidate" always;
}
```

## Research notes

See [`docs/protocol.md`](docs/protocol.md) for the protocol observations intentionally included in this release and [`docs/history.md`](docs/history.md) for the development path from Android-emulator screenshots to direct HLS streaming.

## Compatibility

This is reverse-engineered experimental software, tested against a specific HiChip/Genbolt camera/firmware combination. There is no guarantee that another model or firmware revision uses the same packet sequence, encryption behavior, video format, or wake/discovery behavior.

## Security and responsible use

Use this software only with devices and networks you own or are authorized to test. See [`SECURITY.md`](SECURITY.md). The project intentionally avoids publishing real credentials, device identifiers, private packet captures, and selected opaque session material.

## License

HiChip Streamer is free software released under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)**. See [`LICENSE`](LICENSE) for the full license text.
