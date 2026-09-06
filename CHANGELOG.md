# Changelog

## 0.22.1 - dynamic camera rediscovery

- Fixed a reconnect failure when DHCP changes the camera IPv4 address.
- `--camera-ip` now acts as the preferred camera address; the first valid LAN `F141` response can be adopted from a different IP.
- Added `--strict-camera-ip` for deployments that require the previous fixed-IP behavior.
- Once a camera endpoint is selected, session traffic is restricted to that exact IP/UDP-port tuple.
- Added explicit logging when the configured camera IP differs from the discovered address.
- Completed translation of a few remaining runtime messages/comments to English.
- Renamed the Windows client build to `hichip-client221.exe`.

## 0.22.0 - public release

- Removed real camera IP, wake MAC, and AES video-key defaults.
- Added `HICHIP_WAKE_MAC`, `HICHIP_VIDEO_KEY`, and `HICHIP_PRIVATE_DIR` environment-variable support.
- Moved captured bootstrap and late-session F1D0 packets out of the executable/repository.
- Added local FFmpeg discovery next to the executable before falling back to `PATH`.
- Renamed the Windows client build to `hichip-client220.exe`.
- Translated user-facing text, comments, documentation, and build output to English.
- Added public-release documentation, security guidance, and `.gitignore` rules.
